/*

    IDA trace: PIN tool to communicate with IDA's debugger

*/

#include <pin.H>
#include <portability.H>

#include "idadbg.h"
#include "idadbg_local.h"

//--------------------------------------------------------------------------
// By default we use a separate internal thread for reinstrumentation
// (PIN_RemoveInstrumentation) as there is a a danger of deadlock
// when calling it from listener thread while an application thread is
// waiting on the semaphore. The reason this macro still exists is due to
// idea of future using of PIN_IsActionPending + ExecuteAt from analyze
// routines and thus to get PIN_RemoveInstrumentation chance to be executed
// safely even when called directly from the listener thread
// (more details: http://tech.groups.yahoo.com/group/pinheads/message/6881)
// There is another issue: breakpoints, thread suspends, pausing and
// waiting for resume on events are implemented by waiting on semaphore
// inside callbacks and analysiz routines. So all threads are considered to be
// suspended when an event has been emited and application semaphore cleared:
// we assume that soon thereafter each running thread will be suspended
// on the semaphore inside one of analysis routines. But some threads may be
// waiting somewhere else (system calls and so on). For such threads we can't
// provide the client correct registers as we don't have valid thread context
// stored for them. One of the ways to get valid thread context is to stop
// all threads by PIN_StopApplicationThreads. The problem is that
// PIN_StopApplicationThreads requires every thread to reach a safe point
// (outside of callbacks and analysis routines) so each analysis routine
// should use pair PIN_IsActionPending + ExecuteAt to get PIN chance to stop
// its thread. We can't call ExecuteAt from a callback - we just
// return from a callback in hope the thread will be suspended somewhere else
// (this is not critical for all callbacks but context-change one: so we
// should check and not call PIN_StopApplicationThreads if there is a
// thread waiting inside context-change callback).
#define SEPARATE_THREAD_FOR_REINSTR

//--------------------------------------------------------------------------
// Command line switches
KNOB<int> knob_ida_port(KNOB_MODE_WRITEONCE, "pintool",
    "p", "23946", "Port where IDA Pro is listening for incoming PIN tool's connections");

KNOB<int> knob_connect_timeout(KNOB_MODE_WRITEONCE, "pintool",
    "T", "0", "How many seconds wait for client connection (in seconds, 0 - wait for forever)");

KNOB<int> knob_debug_mode(KNOB_MODE_WRITEONCE, "pintool",
    "idadbg", "0", "Debug mode");

//--------------------------------------------------------------------------
// IDA listener (runs in a separate thread)
static VOID ida_pin_listener(VOID *);
// sockets
static PIN_SOCKET srv_socket, cli_socket;
// internal thread identifier
static PIN_THREAD_UID listener_uid;
// flag: has internal listener thread really started?
static bool listener_ready = false;
// this lock protects 'listener_ready' flag: a thread should acquire it
// when is going to communicate with IDA
PIN_LOCK listener_lock;

//--------------------------------------------------------------------------
// Handle IDA requests
static bool handle_packets(int total, pin_event_id_t until_ev = NO_EVENT);
static bool read_handle_packet(idapin_packet_t *res = NULL);
static bool handle_packet(const idapin_packet_t *res);
static const char *last_packet = "NONE";      // for debug purposes
// We use this function to communicate with IDA synchronously
// while the listener thread is not active
static bool serve_sync(void);

//--------------------------------------------------------------------------
static inline void get_context_regs(const CONTEXT *ctx, idapin_registers_t *regs);
static inline void get_phys_context_regs(const PHYSICAL_CONTEXT *ctx, idapin_registers_t *regs);

//--------------------------------------------------------------------------
// application process state
enum process_state_t
{
  APP_STATE_NONE,          // not started yet -> don't report any event
                           // until the PROCESS_START packet is added
                           // to the events queue
  APP_STATE_RUNNING,       // process thread is running
  APP_STATE_PAUSE,         // pause request received
  APP_STATE_SUSPENDED,     // process suspended - wait for resume
  APP_STATE_WAIT_FLUSH,    // process suspended due to tracebuf is full
  APP_STATE_EXITING,       // process thread is exiting
  APP_STATE_DETACHED,      // detached
};

// global process state variable and lock for it
static process_state_t process_state = APP_STATE_NONE;
static PIN_LOCK process_state_lock;

//--------------------------------------------------------------------------
// break at the very next instruction?
static bool break_at_next_inst = false;

// semaphore used for pausing the whole application
static PIN_SEMAPHORE run_app_sem;

// main thread id: we don't emit THREAD_START event for it
// as IDA registers main thread when handles PROCESS_START event
static THREADID main_thread = INVALID_THREADID;

static pin_debug_event_t attach_ev;

//--------------------------------------------------------------------------
// thread-local data
class thread_data_t
{
public:
  inline thread_data_t();
  ~thread_data_t();

  bool ctx_ok() const                  { return ctx != NULL; }
  CONTEXT *get_ctx()                   { create_ctx(); return ctx; }
  inline void suspend();
  inline void wait();
  inline void resume();
  inline void set_excp_handled(bool val);

  bool suspended() const               { return susp; }
  bool excp_handled() const            { return ev_handled; }
  inline pin_thid get_ext_tid() const  { return ext_tid; }
  inline void save_ctx(const CONTEXT *src_ctx);
  inline void save_ctx_regs(const idapin_registers_t *srci_ctx_regs);
  inline void drop_ctx_regs();

  inline void export_ctx(idapin_registers_t *regs);

  static int nthreads()                { return thread_cnt;   }
  static int nsuspended()              { return suspeded_cnt; }
  static bool have_suspended_threads() { return suspeded_cnt != 0; }
  static bool all_threads_suspended()  { return thread_cnt != 0 && suspeded_cnt == thread_cnt; }

  static inline thread_data_t *get_thread_data();
  static inline thread_data_t *get_thread_data(THREADID tid);
  static inline CONTEXT *get_thread_context(THREADID tid);
  static inline bool release_thread_data(THREADID tid);

  static inline THREADID get_thread_id();
  static inline pin_thid get_ext_thread_id(THREADID locat_tid);
  static inline THREADID get_local_thread_id(pin_thid tid_ext);

  static inline thread_data_t *get_any_stopped_thread();

private:
  void create_ctx()                    { if ( !ctx_ok() ) ctx = new CONTEXT; }
  inline void try_init_ext_tid(THREADID locat_tid);
  inline void set_ext_tid(THREADID locat_tid, pin_thid tid);

  CONTEXT *ctx;
  const idapin_registers_t *ctx_regs; // NULL if not defined->will get from ctx
  PIN_SEMAPHORE thr_sem;
  PIN_LOCK ctx_lock;
  pin_thid ext_tid;
  bool susp;
  bool ev_handled;     // true if the last exception was hanlded by debugger
  static int thread_cnt;
  static int suspeded_cnt;
  typedef std::map <THREADID, thread_data_t *> thrdata_map_t;
  static thrdata_map_t thr_data;
  static std::map <pin_thid, THREADID> local_tids;
  static PIN_LOCK thr_data_lock;
  static bool thr_data_lock_inited;
};

//--------------------------------------------------------------------------
// Event queue
class ev_queue_t
{
public:
  ev_queue_t();
  ~ev_queue_t();
  //lint -sem(ev_queue_t::init,initializer)
  void init();
  inline void push_back(const pin_debug_event_t &ev);
  inline void push_front(const pin_debug_event_t &ev);
  inline bool pop_front(pin_debug_event_t *out_ev);
  inline bool back(pin_debug_event_t *out_ev);
  inline size_t size();
  inline bool empty();
  inline void last_ev(pin_debug_event_t *out_ev);

private:
  inline void add_ev(const pin_debug_event_t &ev, bool front);
  typedef std::deque<pin_debug_event_t> event_list_t;
  event_list_t queue;
  PIN_LOCK lock;
  pin_debug_event_t last_retrieved_ev;
};

//--------------------------------------------------------------------------
// Manager of breakpoints, pausing, stepping, thread susending
class bpt_mgr_t
{
public:
  bpt_mgr_t();
  ~bpt_mgr_t();
  //lint -sem(bpt_mgr_t::cleanup,initializer)
  inline void cleanup();

  // return values: true - bpt really added/removed, false - else
  inline void add_soft_bpt(ADDRINT at);
  inline void del_soft_bpt(ADDRINT at);

  // have bpt at given address?
  inline bool have_bpt_at(ADDRINT addr);

  // set stepping thread ID
  inline void set_step(THREADID stepping_tid);

  // inform bpt_mgr that we are about to suspend/resume
  // return value:
  //   true - need reinstrumentation
  inline bool prepare_resume();
  inline void prepare_suspend();

  // instrumentation callback: add analysis routines
  inline void add_rtns(INS ins, ADDRINT ins_addr);

  // IfCall callback for ctrl_rtn (should be inlined by PIN; run tool  with
  // -log_inline command line option to check what routines PIN really inlines)
  static ADDRINT ctrl_rtn_enabled();

  bool need_control_cb() const;
  inline void update_ctrl_flag() const;

private:
  enum ev_id_t
  {
    EV_PAUSED       = 0,
    EV_SINGLE_STEP  = 1,
    EV_BPT          = 2,
    EV_INITIAL_STOP = 3,
    EV_NO_EVENT     = 4
  };
  typedef std::set<ADDRINT> addrset_t;

  inline bool have_bpt_at_nolock(ADDRINT addr);

  // analysis routines
  static void PIN_FAST_ANALYSIS_CALL bpt_rtn(ADDRINT addr, const CONTEXT *ctx);
  static void PIN_FAST_ANALYSIS_CALL ctrl_rtn(ADDRINT addr, const CONTEXT *ctx);

  inline void do_bpt(ADDRINT addr, const CONTEXT *ctx);
  inline void do_ctrl(ADDRINT addr, const CONTEXT *ctx);
  void emit_event(ev_id_t eid, ADDRINT addr, THREADID tid);

  static bool control_enabled;

  addrset_t bpts;
  // Sometimes PIN starts reinstrumenting not immediately but after some period.
  // So during this period we keep newly added bpts in the special set
  // (pending_bpts) and handle them in ctrl_rtn until we detect
  // reinstrumentation really started. Note that using ctrl_rtn for breakpoints
  // can dramatically slow down the execution so we will try to get rid
  // of such pending breakpoints as soon as possible
  addrset_t pending_bpts;
  // thread ID of the last dbg_thread_set_step request
  THREADID stepping_thread;
  // this lock controls access to breakpoints
  PIN_LOCK bpt_lock;
  // true if we need to reinstrument just after resume
  bool need_reinst;
};

//--------------------------------------------------------------------------
// This class implements analysis routines, instrumentation callbacks,
// init/update instrumentation according to client's requests
class instrumenter_t
{
public:
  static bool init();
  static bool finish();
  static void init_instrumentations();
  static void update_instrumentation(uint32 trace_types);
  static inline void reinit_instrumentations();
  static inline void remove_instrumentations();
  static inline void resume();

  static inline size_t tracebuf_size();
  static inline bool tracebuf_is_full();
  static inline void clear_trace();
  static int get_trace_events(idatrace_events_t *out_trc_events);
  static bool set_limits(bool only_new, uint32 enq_size, const char *imgname);
  static void process_image(const IMG &img, bool as_default);

  enum instr_state_t
  {
    INSTR_STATE_INITIAL,
    INSTR_STATE_NEED_REINIT,
    INSTR_STATE_REINIT_STARTED,
    INSTR_STATE_OK,
  };
  static inline bool instr_state_ok();

private:
  static void add_instrumentation(trace_flags_t inst);

  // logic IF-routines (should be inlined by PIN; run tool with -log_inline
  // command line option to check what routines PIN does really inline)
  static ADDRINT ins_enabled(VOID *);
  static ADDRINT trc_enabled(VOID *);
  static ADDRINT rtn_enabled(VOID *);

  // logic THEN-routines
  static VOID PIN_FAST_ANALYSIS_CALL ins_logic_cb(
        const CONTEXT *ctx,
        VOID *ip,
        pin_tev_type_t tev_type);
  static VOID PIN_FAST_ANALYSIS_CALL rtn_logic_cb(
        ADDRINT ins_ip,
        ADDRINT target_ip,
        BOOL is_indirect,
        BOOL is_ret);
  static inline void store_trace_entry(
        const CONTEXT *ctx,
        ADDRINT ea,
        pin_tev_type_t tev_type);
  static inline void add_to_trace(
        const CONTEXT *ctx,
        ADDRINT ea,
        pin_tev_type_t tev_type);
  static inline void add_to_trace(ADDRINT ea, pin_tev_type_t tev_type);
  static inline void prepare_and_wait_trace_flush();
  static inline void register_recorded_insn(ADDRINT addr);
  static inline bool insn_is_registered(ADDRINT addr);
  static inline bool check_address(ADDRINT addr);
  static inline bool check_address(ADDRINT addr, pin_tev_type_t type);

  // instrumentation callbacks: insert logic routines
  static VOID instruction_cb(INS ins, VOID *);
  static VOID trace_cb(TRACE trace, VOID *);
  static VOID routine_cb(TRACE trace, VOID *);
  static bool add_bbl_logic_cb(INS ins, bool first);
  static bool add_rtn_logic_cb(INS ins);

  static uint32 curr_trace_types();

  // recorded instructions
  typedef std::deque<trc_element_t> trc_deque_t;
  static PIN_LOCK tracebuf_lock;
  static trc_deque_t trace_addrs;
  // semaphore used for pausing when trace buffer is full
  static PIN_SEMAPHORE tracebuf_sem;

  // Already recorded instructions, those should be skipped if
  // only_new_instructions flag is true.
  // NOTE: as we have limited memory in the PIN tool we cannot let it grow
  // without limit, we need to remember a maximum number of "skip_limit"
  // element(s), or the PIN tool would die because it runs out of memory
  typedef std::deque<ADDRINT> addr_deque_t;
  static addr_deque_t all_addrs;
  // only record new instructions?
  static bool only_new_instructions;
  // do not limit tracing addrs by image boundaries (min_address/max_address)
  static bool trace_everything;
  // max trace buffer size (max number of events in the buffer)
  static uint32 enqueue_limit;
  // remember only the last 1 million instructions
  static const uint32 skip_limit;
  // limits to filter what to record
  static ADDRINT min_address;
  static ADDRINT max_address;
  // name of the image to trace
  static string image_name;

  static instr_state_t state;

  // trace mode switches
  static bool tracing_instruction;
  static bool tracing_bblock;
  static bool tracing_routine;
  static bool tracing_registers;
  static bool log_ret_isns;

  static uchar instrumentations;

#ifdef SEPARATE_THREAD_FOR_REINSTR
  static VOID reinstrumenter(VOID *);
  static bool reinstr_started;
  static PIN_SEMAPHORE reinstr_sem;
  static PIN_THREAD_UID reinstr_uid;
#endif
};

//--------------------------------------------------------------------------
// Logging/debug
static int debug_level = 0;

// queued events
static ev_queue_t events;

// iThe folowing object manages bpt/pausing/single step/thread suspend
static bpt_mgr_t breakpoints;

//--------------------------------------------------------------------------
// the following functions access process state; they don't acquire
// process_state_lock, it MUST be acquired by caller
static inline bool process_started()
{
  return process_state != APP_STATE_NONE;
}

//--------------------------------------------------------------------------
static inline bool process_exiting()
{
  return process_state == APP_STATE_EXITING;
}

//--------------------------------------------------------------------------
static inline bool process_detached()
{
  return process_state == APP_STATE_DETACHED;
}

//--------------------------------------------------------------------------
static inline bool process_pause()
{
  return process_state == APP_STATE_PAUSE;
}

//--------------------------------------------------------------------------
static inline bool process_suspended()
{
  return process_state == APP_STATE_SUSPENDED
      || process_state == APP_STATE_WAIT_FLUSH;
}

//--------------------------------------------------------------------------
inline       char *tail(      char *in_str) { return strchr(in_str, '\0'); }
inline const char *tail(const char *in_str) { return strchr(in_str, '\0'); }

//--------------------------------------------------------------------------
static inline ADDRINT get_ctx_ip(const CONTEXT *ctx)
{
  return ctx==NULL ? BADADDR : (ADDRINT)PIN_GetContextReg(ctx, REG_INST_PTR);
}

//--------------------------------------------------------------------------
static inline void get_context_regs(const CONTEXT *ctx, idapin_registers_t *regs)
{
  regs->eax = (ADDRINT)PIN_GetContextReg(ctx, REG_GAX);
  regs->ebx = (ADDRINT)PIN_GetContextReg(ctx, REG_GBX);
  regs->ecx = (ADDRINT)PIN_GetContextReg(ctx, REG_GCX);
  regs->edx = (ADDRINT)PIN_GetContextReg(ctx, REG_GDX);
  regs->esi = (ADDRINT)PIN_GetContextReg(ctx, REG_GSI);
  regs->edi = (ADDRINT)PIN_GetContextReg(ctx, REG_GDI);
  regs->ebp = (ADDRINT)PIN_GetContextReg(ctx, REG_GBP);
  regs->esp = (ADDRINT)PIN_GetContextReg(ctx, REG_STACK_PTR);
  regs->eip = (ADDRINT)PIN_GetContextReg(ctx, REG_INST_PTR);
#if defined(PIN_64)
  regs->r8  = (ADDRINT)PIN_GetContextReg(ctx, REG_R8);
  regs->r9  = (ADDRINT)PIN_GetContextReg(ctx, REG_R9);
  regs->r10 = (ADDRINT)PIN_GetContextReg(ctx, REG_R10);
  regs->r11 = (ADDRINT)PIN_GetContextReg(ctx, REG_R11);
  regs->r12 = (ADDRINT)PIN_GetContextReg(ctx, REG_R12);
  regs->r13 = (ADDRINT)PIN_GetContextReg(ctx, REG_R13);
  regs->r14 = (ADDRINT)PIN_GetContextReg(ctx, REG_R14);
  regs->r15 = (ADDRINT)PIN_GetContextReg(ctx, REG_R15);

  regs->eflags = (ADDRINT)PIN_GetContextReg(ctx, REG_RFLAGS);
#else
  regs->eflags = (ADDRINT)PIN_GetContextReg(ctx, REG_EFLAGS);
#endif
  regs->cs = (ADDRINT)PIN_GetContextReg(ctx, REG_SEG_CS);
  regs->ds = (ADDRINT)PIN_GetContextReg(ctx, REG_SEG_DS);
  regs->es = (ADDRINT)PIN_GetContextReg(ctx, REG_SEG_ES);
  regs->fs = (ADDRINT)PIN_GetContextReg(ctx, REG_SEG_FS);
  regs->gs = (ADDRINT)PIN_GetContextReg(ctx, REG_SEG_GS);
  regs->ss = (ADDRINT)PIN_GetContextReg(ctx, REG_SEG_SS);
}

//--------------------------------------------------------------------------
static inline void get_phys_context_regs(const PHYSICAL_CONTEXT *ctx, idapin_registers_t *regs)
{
  regs->eax = (ADDRINT)PIN_GetPhysicalContextReg(ctx, REG_GAX);
  regs->ebx = (ADDRINT)PIN_GetPhysicalContextReg(ctx, REG_GBX);
  regs->ecx = (ADDRINT)PIN_GetPhysicalContextReg(ctx, REG_GCX);
  regs->edx = (ADDRINT)PIN_GetPhysicalContextReg(ctx, REG_GDX);
  regs->esi = (ADDRINT)PIN_GetPhysicalContextReg(ctx, REG_GSI);
  regs->edi = (ADDRINT)PIN_GetPhysicalContextReg(ctx, REG_GDI);
  regs->ebp = (ADDRINT)PIN_GetPhysicalContextReg(ctx, REG_GBP);
  regs->esp = (ADDRINT)PIN_GetPhysicalContextReg(ctx, REG_STACK_PTR);
  regs->eip = (ADDRINT)PIN_GetPhysicalContextReg(ctx, REG_INST_PTR);
#if defined(PIN_64)
  regs->r8  = (ADDRINT)PIN_GetPhysicalContextReg(ctx, REG_R8);
  regs->r9  = (ADDRINT)PIN_GetPhysicalContextReg(ctx, REG_R9);
  regs->r10 = (ADDRINT)PIN_GetPhysicalContextReg(ctx, REG_R10);
  regs->r11 = (ADDRINT)PIN_GetPhysicalContextReg(ctx, REG_R11);
  regs->r12 = (ADDRINT)PIN_GetPhysicalContextReg(ctx, REG_R12);
  regs->r13 = (ADDRINT)PIN_GetPhysicalContextReg(ctx, REG_R13);
  regs->r14 = (ADDRINT)PIN_GetPhysicalContextReg(ctx, REG_R14);
  regs->r15 = (ADDRINT)PIN_GetPhysicalContextReg(ctx, REG_R15);

  regs->eflags = (ADDRINT)PIN_GetPhysicalContextReg(ctx, REG_RFLAGS);
#else
  regs->eflags = (ADDRINT)PIN_GetPhysicalContextReg(ctx, REG_EFLAGS);
#endif
  regs->cs = (ADDRINT)PIN_GetPhysicalContextReg(ctx, REG_SEG_CS);
  regs->ds = (ADDRINT)PIN_GetPhysicalContextReg(ctx, REG_SEG_DS);
  regs->es = (ADDRINT)PIN_GetPhysicalContextReg(ctx, REG_SEG_ES);
  regs->fs = (ADDRINT)PIN_GetPhysicalContextReg(ctx, REG_SEG_FS);
  regs->gs = (ADDRINT)PIN_GetPhysicalContextReg(ctx, REG_SEG_GS);
  regs->ss = (ADDRINT)PIN_GetPhysicalContextReg(ctx, REG_SEG_SS);
}

//--------------------------------------------------------------------------
static inline void emit_suspend_ev(uint32 eid, ea_t ea, pin_thid ext_tid)
{
  pin_debug_event_t event;
  event.bpt.hea = BADADDR;
  event.bpt.kea = BADADDR;
  if ( eid == PROCESS_ATTACH )
    event = attach_ev;
  event.eid = eid;
  event.ea = ea;
  event.tid = ext_tid;
  events.push_back(event);
}

//--------------------------------------------------------------------------
static inline bool pop_debug_event(pin_debug_event_t *out_ev)
{
  if ( !events.pop_front(out_ev)  )
    return false;
  if ( out_ev->tid == NO_THREAD )
  {
    thread_data_t *td = thread_data_t::get_any_stopped_thread();
    if ( td == NULL )
    {
      MSG("PINtool error: undefined event TID and no stopped thread found\n");
    }
    else
    {
      out_ev->tid = td->get_ext_tid();
      CONTEXT *ctx = td->get_ctx();
      out_ev->ea = get_ctx_ip(ctx);
      DEBUG(2, "pop event->correct tid(%d)/ea(%p)\n", out_ev->tid, (void *)addr_t(out_ev->ea));
    }
  }
  return true;
}

//--------------------------------------------------------------------------
// prepare suspend (don't acquire process_state_lock, it must be done by caller)
static inline void do_suspend_nolock(process_state_t new_state)
{
  if ( !process_suspended() )
  {
    if ( new_state == APP_STATE_WAIT_FLUSH )
    {
      MSG("do_suspend_nolock - invalid state APP_STATE_WAIT_FLUSH\n");
      exit(-1);
    }
    sema_clear(&run_app_sem);
    process_state = new_state;
    DEBUG(2, "do_suspend_nolock(%d)\n", int(new_state));
    breakpoints.prepare_suspend();
  }
}

//--------------------------------------------------------------------------
// fill some common fields of event and add it to the queue
static inline void enqueue_event(pin_debug_event_t &ev, THREADID tid)
{
  ev.pid = PIN_GetPid();
  ev.tid = thread_data_t::get_ext_thread_id(tid);
  ev.handled = false;
  events.push_back(ev);
}

//--------------------------------------------------------------------------
static inline void enqueue_event(pin_debug_event_t &ev)
{
  enqueue_event(ev, thread_data_t::get_thread_id());
}

//--------------------------------------------------------------------------
// fill some common fields of event, add it to the queue and suspend process
static inline void suspend_at_event(pin_debug_event_t &ev, THREADID tid)
{
  janitor_for_pinlock_t process_state_guard(&process_state_lock);
  if ( !process_detached() && !process_exiting() )
  {
    enqueue_event(ev, tid);
    do_suspend_nolock(APP_STATE_SUSPENDED);
  }
}

//--------------------------------------------------------------------------
static inline void suspend_at_event(pin_debug_event_t &ev)
{
  suspend_at_event(ev, thread_data_t::get_thread_id());
}

//--------------------------------------------------------------------------
static inline bool wait_for_thread_termination(PIN_THREAD_UID tuid)
{
  return PIN_WaitForThreadTermination(tuid, 10000, NULL);
}

//--------------------------------------------------------------------------
// This function is called when the application exits
static VOID fini_cb(INT32 code, VOID *)
{
  pin_debug_event_t evt(PROCESS_EXIT);
  evt.exit_code = code;
  enqueue_event(evt);

  MSG("Waiting for internal threads to exit...\n");
  if ( wait_for_thread_termination(listener_uid) && instrumenter_t::finish() )
    MSG("Everything OK\n");
  else
    MSG("Timeout waiting for internal thread.\n");
}

//--------------------------------------------------------------------------
// Pin calls this function every time an img is loaded
//lint -e{1746} parameter 'img' could be made const reference
static VOID image_load_cb(IMG img, VOID *)
{
  ADDRINT start_ea = IMG_LowAddress(img);
  ADDRINT end_ea = IMG_HighAddress(img);

  MSG("Loading library %s %p:%p\n", IMG_Name(img).c_str(), (void*)start_ea, (void*)end_ea);

  pin_debug_event_t event(LIBRARY_LOAD);
  event.ea = IMG_Entry(img);
  pin_strncpy(event.modinfo.name, IMG_Name(img).c_str(), sizeof(event.modinfo.name));
  event.modinfo.base = start_ea;
  event.modinfo.size = (pin_size_t)(end_ea - start_ea);
  event.modinfo.rebase_to = BADADDR;
  enqueue_event(event);

  instrumenter_t::process_image(img, false);
}

//--------------------------------------------------------------------------
// Pin calls this function every time an img is unloaded
// You can't instrument an image that is about to be unloaded
//lint -e{1746} parameter 'img' could be made const reference
static VOID image_unload_cb(IMG img, VOID *)
{
  pin_debug_event_t ev(LIBRARY_UNLOAD);
  ev.ea      = BADADDR;
  pin_strncpy(ev.info, IMG_Name(img).c_str(), sizeof(ev.info));
  enqueue_event(ev);

  MSG("Unloading %s\n", IMG_Name(img).c_str());
}

//--------------------------------------------------------------------------
// This routine is executed every time a thread is created
//lint -e{818} Pointer parameter 'ctx' could be declared as pointing to const
static VOID thread_start_cb(THREADID tid, CONTEXT *ctx, INT32, VOID *)
{
  thread_data_t *tdata = thread_data_t::get_thread_data(tid);
  tdata->save_ctx(ctx);

  DEBUG(2, "thread_start_cb(%d/%d)\n", int(tid), int(thread_data_t::get_ext_thread_id(tid)));

  // do not emit THREAD_START if we are inside main thread:
  // IDA has stored main thread when processed PROCESS_START event
  if ( tid != main_thread )
  {
    pin_debug_event_t ev(THREAD_START);
    ev.ea = get_ctx_ip(ctx);
    suspend_at_event(ev, tid);
    DEBUG(2, "THREAD START: %d AT %p\n", ev.tid, (void *)addr_t(ev.ea));

    wait_after_callback();
  }
}

//--------------------------------------------------------------------------
// This routine is executed every time a thread is destroyed.
static VOID thread_fini_cb(THREADID tid, const CONTEXT *ctx, INT32 code, VOID *)
{
  thread_data_t *tdata = thread_data_t::get_thread_data(tid);
  tdata->save_ctx(ctx);

  pin_debug_event_t ev(THREAD_EXIT);
  ev.exit_code = code;
  ev.ea = get_ctx_ip(ctx);
  DEBUG(2, "THREAD FINISH: %d AT %p\n", tid, (void *)addr_t(ev.ea));
  suspend_at_event(ev, tid);

  wait_after_callback();
}

//--------------------------------------------------------------------------
static INT32 usage()
{
  fprintf(stderr, "Pin Tool to communicate with IDA's debugger\n");
  fprintf(stderr, "\n%s\n", KNOB_BASE::StringKnobSummary().c_str());
  return -1;
}

//--------------------------------------------------------------------------
static void exit_process(int code)
{
  process_state = APP_STATE_EXITING;
  sema_set(&run_app_sem);
  PIN_ExitProcess(code);
}

//--------------------------------------------------------------------------
static void detach_process()
{
  process_state = APP_STATE_DETACHED;
  sema_set(&run_app_sem);
  PIN_Detach();
}

//--------------------------------------------------------------------------
inline static void error_msg(const char *msg)
{
  MSG("%s: %s\n", msg, strerror(errno));
}

//--------------------------------------------------------------------------
static bool sockets_startup(void)
{
  bool ret = true;
#ifdef _WIN32
  WINDOWS::WORD wVersionRequested = 0x0202;
  WINDOWS::WSADATA wsaData;
  int err = WINDOWS::WSAStartup(wVersionRequested, &wsaData);
  if ( err != 0 )
  {
    error_msg("WSAStartup");
    ret = false;
  }
#endif
  return ret;
}

//--------------------------------------------------------------------------
static void check_network_error(ssize_t ret, const char *from_where)
{
  if ( ret == -1 )
  {
#ifdef _WIN32
    int err = WINDOWS::WSAGetLastError();
    bool timeout = err == WSAETIMEDOUT;
#else
    int err = errno;
    bool timeout = err == EAGAIN;
#endif
    if ( !timeout )
    {
      MSG("A network error %d happened in %s, exiting from application...\n", err, from_where);
      exit_process(-1);
    }
    MSG("Timeout, called from %s\n", from_where);
  }
}

//--------------------------------------------------------------------------
static ssize_t pin_recv(PIN_SOCKET fd, void *buf, size_t n, const char *from_where)
{
  char *bufp = (char*)buf;
  ssize_t total = 0;
  while ( n > 0 )
  {
    ssize_t ret;
#ifdef _WIN32
    ret = WINDOWS::recv(fd, bufp, (int)n, 0);
#else
    do
      ret = recv(fd, bufp, n, 0);
    while ( ret == -1 && errno == EINTR );
#endif
    check_network_error(ret, from_where);
    if ( ret <= 0 )
      return ret;
    n -= ret;
    bufp += ret;
    total += ret;
  }
  return total;
}

//--------------------------------------------------------------------------
static ssize_t pin_send(PIN_SOCKET fd, const void *buf, size_t n, const char *from_where)
{
  ssize_t ret;
#ifdef _WIN32
  ret = WINDOWS::send(fd, (const char *)buf, (int)n, 0);
#else
  do
    ret = send(fd, buf, n, 0);
  while ( ret == -1 && errno == EINTR );
#endif
  check_network_error(ret, from_where);
  return ret;
}

//--------------------------------------------------------------------------
static const char *const packet_names[] =
{
  "ACK",            "ERROR",       "HELLO",       "EXIT PROCESS",
  "START PROCESS",  "DEBUG EVENT", "READ EVENT",  "MEMORY INFO",
  "READ MEMORY",    "DETACH",      "COUNT TRACE", "READ TRACE",
  "CLEAR TRACE",    "PAUSE",       "RESUME",      "RESUME START",
  "ADD BPT",        "DEL BPT",     "RESUME BPT",  "CAN READ REGS",
  "READ REGS",      "SET TRACE",   "SET OPTIONS", "STEP INTO",
  "THREAD SUSPEND", "THREAD RESUME"
};

//--------------------------------------------------------------------------
static bool send_packet(
  const void *pkt,
  size_t size,
  void *answer,
  size_t ans_size,
  const char *from)
{
  ssize_t bytes = pin_send(cli_socket, pkt, size, from);
  if ( bytes > -1 )
  {
    if ( answer != NULL )
      bytes = pin_recv(cli_socket, answer, ans_size, from);
  }
  return bytes > 0;
}

//--------------------------------------------------------------------------
static bool accept_conn()
{
  struct pin_sockaddr_in sa;
  pin_socklen_t clilen = sizeof(sa);
  //lint -e565 tag 'sockaddr' not previously seen, assumed file-level scope
  cli_socket = pin_accept(srv_socket, ((struct sockaddr *)&sa), &clilen);
  if ( cli_socket == INVALID_SOCKET )
    return false;
  // accepted, client should send 'hello' packet, read it
  // read version 1 packet as it is may be shorter than the modern one
  idapin_packet_v1_t req_v1;
  DEBUG(4, "Receiving packet, expected %d bytes...\n",(uint32)sizeof(req_v1));
  int bytes = pin_recv(cli_socket, &req_v1, sizeof(req_v1), "read_handle_packet");
  if ( bytes <= 0 )
  {
    if ( bytes != 0 )
      MSG("recv: connection closed by peer\n");
    else
      error_msg("recv");
    return false;
  }
  if ( req_v1.code != PTT_HELLO )
  {
    if ( req_v1.code > PTT_END )
      MSG("Unknown packet type %d\n", req_v1.code);
    else
      MSG("'HELLO' expected, '%s' received)\n", packet_names[req_v1.code]);
    return false;
  }
  if ( req_v1.size == 1 )
  {
    // version 1 (incompatible) client - send v1 packet answer and exit
    MSG("Incompatible client (version 1) - disconnect\n");
    req_v1.size = PIN_PROTOCOL_VERSION;
    req_v1.data = sizeof(ADDRINT);
    req_v1.code = PTT_ACK;
    send_packet(&req_v1, sizeof(req_v1), NULL, 0, __FUNCTION__);
    pin_closesocket(cli_socket);
    return false;
  }
  // valid client: read the rest of 'hello' packed
  idapin_packet_t req;
  memcpy(&req, &req_v1, sizeof(idapin_packet_v1_t));
  int rest = sizeof(idapin_packet_t) - sizeof(idapin_packet_v1_t);
  if ( rest > 0 )
  {
    char *ptr = (char *)&req + sizeof(idapin_packet_v1_t);
    if ( pin_recv(cli_socket, ptr, rest, "accept_conn") != rest )
      return false;
  }
  // response: we send target OS id and the size of ADDRINT to let the client
  // know if we're using the correct IDA version (32 or 64 bits)
  idapin_packet_t ans;
  ans.data = sizeof(ADDRINT) | addr_t(TARGET_OS);
  // ...and the version of the protocol
  ans.size = PIN_PROTOCOL_VERSION;
  ans.code = PTT_ACK;
  if ( !send_packet(&ans, sizeof(idapin_packet_t), NULL, 0, __FUNCTION__) )
    return false;

  return true;
}

//--------------------------------------------------------------------------
static bool init_socket(void)
{
  int portno = knob_ida_port;

  sockets_startup();
  srv_socket = socket(AF_INET, SOCK_STREAM, 0);
  if ( srv_socket == (PIN_SOCKET)-1 )
  {
    error_msg("socket");
    return false;
  }

  int optval = 1;
  pin_setsockopt(srv_socket, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));

  struct pin_sockaddr_in sa;
  memset(&sa, '\0', sizeof(sa));
  sa.sin_family = AF_INET;
  sa.sin_port   = pin_htons(portno);
  if ( pin_bind(srv_socket, (pin_sockaddr *)&sa, sizeof(sa)) != 0 )
  {
    error_msg("bind");
    return false;
  }

  if ( pin_listen(srv_socket, 1) == 0 )
  {
    MSG("Listening at port %d...\n", (int)portno);

    int to = knob_connect_timeout;

    if ( to != 0 )
    {
      pin_timeval tv;
      pin_fd_set read_descs;
      tv.tv_sec = to;
      tv.tv_usec = 0;
      FD_ZERO(&read_descs);
      FD_SET(srv_socket, &read_descs);
      if( select(srv_socket + 1, &read_descs, NULL, NULL, &tv) == -1 )
      {
        error_msg("select");
        return false;
      }
      if( !FD_ISSET(srv_socket, &read_descs) )
      {
        MSG("client connect timeout\n");
        return false;
      }
    }
    return accept_conn();
  }
  return false;
}

//--------------------------------------------------------------------------
// On Windows internal threads are blocked until the application
// has finished initializing its DLL's.
// So, at first we use synchronous function serve_sync() to wait for resume
// packet after breakpoint/pause/trace buffer transferring.
// We stop using synchronous serving when the listener thread really starts
static inline void wait_app_resume(PIN_SEMAPHORE *sem)
{
  if ( !serve_sync() )
  {
    // Don't know what to do if serve_sync() fails: just set semaphore
    // (to avoid deadlock) and return. Would it be better to exit application?
    sema_set(sem);
  }
  sema_wait(sem);
}

//--------------------------------------------------------------------------
static VOID app_start_cb(VOID *)
{
  DEBUG(2, "Setting process started to true\n");
  process_state = APP_STATE_RUNNING;
  main_thread = thread_data_t::get_thread_id();

  IMG img;
  img.invalidate();
  for( img = APP_ImgHead(); IMG_Valid(img); img = IMG_Next(img) )
  {
    if ( IMG_IsMainExecutable(img) )
      break;
  }

  if ( !img.is_valid() )
  {
    MSG("Cannot find the 1st instruction of the main executable!\n");
    abort();
  }

  // by default, we set the limits of the trace to the main binary
  ADDRINT start_ea = IMG_LowAddress(img);
  ADDRINT end_ea = IMG_HighAddress(img);

  pin_debug_event_t event(PROCESS_START);
  event.ea = IMG_Entry(img);
  pin_strncpy(event.modinfo.name, IMG_Name(img).c_str(), sizeof(event.modinfo.name));

  event.modinfo.base = start_ea;
  event.modinfo.rebase_to = BADADDR;
  event.modinfo.size = (uint32)(end_ea - start_ea);

  if ( PIN_IsAttaching() )
    attach_ev = event;
  suspend_at_event(event, main_thread);

  // Mistery: in wow64 the app_start_cb callback can be called twice?
  static bool app_start_cb_called = false;
  if ( !app_start_cb_called )
  {
    app_start_cb_called = true;
    MSG("Head image: %s Start %p End %p\n", IMG_Name(img).c_str(), (void*)start_ea, (void*)end_ea);
    instrumenter_t::process_image(img, true);
  }

  // Handle packets in the main thread until we receive the RESUME request
  // to PROCESS_START event
  // We need this to add breakpoints before the application's code is
  // executed, otherwise, we will run into race conditions
  if ( !handle_packets(-1, PROCESS_START) )
  {
    MSG("Error handling initial requests, exiting...\n");
    exit_process(-1);
    return;
  }
  MSG("All breakpoints seems to be added, running the application...\n");
}

//--------------------------------------------------------------------------
static VOID context_change_cb(
  THREADID tid,
  CONTEXT_CHANGE_REASON reason,
  const CONTEXT *ctxt_from,
  CONTEXT *ctxt_to,
  INT32 sig,
  VOID *)
{
  pin_debug_event_t event(EXCEPTION);
  event.exc.code = sig;
  thread_data_t *tdata = thread_data_t::get_thread_data(tid);
  if ( ctxt_from != NULL )
  {
    tdata->save_ctx(ctxt_from);
    event.ea = get_ctx_ip(ctxt_from);
  }
  event.exc.ea = event.ea;

  switch ( reason )
  {
    case CONTEXT_CHANGE_REASON_FATALSIGNAL:
      event.exc.can_cont = false;
      snprintf(event.exc.info, sizeof(event.exc.info), "Fatal signal %d at 0x"HEX64T_FMT"", sig, event.ea);
      break;
    case CONTEXT_CHANGE_REASON_SIGNAL:
      snprintf(event.exc.info, sizeof(event.exc.info), "Signal %d at 0x"HEX64T_FMT"", sig, event.ea);
      break;
    case CONTEXT_CHANGE_REASON_EXCEPTION:
      snprintf(event.exc.info, sizeof(event.exc.info), "Exception 0x%x at address 0x"HEX64T_FMT"", sig, event.ea);
      break;
    case CONTEXT_CHANGE_REASON_SIGRETURN:
      MSG("Context changed: signal return %d at 0x"HEX64T_FMT"\n", sig, event.ea);
      return;
    case CONTEXT_CHANGE_REASON_APC:
      MSG("Context changed: Asynchronous Process Call %d at 0x"HEX64T_FMT"\n", sig, event.ea);
      return;
    case CONTEXT_CHANGE_REASON_CALLBACK:
      MSG("Context changed: Windows Call-back %d at 0x"HEX64T_FMT"\n", sig, event.ea);
      return;
    default:
      MSG("Context changed at 0x"HEX64T_FMT": unknown reason %d\n", event.ea, int(reason));
      return;
  }
  tdata->set_excp_handled(false);
  suspend_at_event(event, tid);

  MSG("EXCEPTION at %p -> %p (thread %d)\n", (void *)addr_t(event.ea),
            (void *)PIN_GetContextReg(ctxt_to, REG_INST_PTR), int(event.tid));

  app_wait(&run_app_sem);
  if ( tdata->excp_handled() )
  {
    if ( reason == CONTEXT_CHANGE_REASON_EXCEPTION && sig == INT32(0x80000003) )
    {
      // I don't know why but trying to mask int3 we pass control
      // to the same address (resulting the same exception) and will
      // run into infinite loop
      // So we don't mask the exception and continue execution
      MSG("Don't mask INT3 exception to avoid infinite loop\n");
    }
    else
    {
      MSG("Mask exception\n");
      PIN_SaveContext(ctxt_from, ctxt_to);
    }
  }
  else
  {
    MSG("Pass exception to the application\n");
  }
}

//--------------------------------------------------------------------------
//lint -e{818} Pointer parameter 'ctxt' could be declared as pointing to const
//                            'ex_info' could be declared as pointing to const
static EXCEPT_HANDLING_RESULT internal_excp_cb(
  THREADID tid,
  EXCEPTION_INFO *ex_info,
  PHYSICAL_CONTEXT *ctxt,
  VOID * /* v */)
{
  pin_debug_event_t event(EXCEPTION);
  event.exc.code = PIN_GetExceptionCode(ex_info);
  event.ea = ea_t(PIN_GetExceptionAddress(ex_info));
  event.exc.ea = event.ea;
  string strinfo = PIN_ExceptionToString(ex_info);
  strncpy(event.exc.info, strinfo.c_str(), sizeof(event.exc.info));
  thread_data_t *tdata = thread_data_t::get_thread_data(tid);
  idapin_registers_t regs;
  get_phys_context_regs(ctxt, &regs);
  tdata->save_ctx_regs(&regs);

  MSG("INTERNAL EXCEPTION (thread %d, code=%x): %s\n", int(tid), event.exc.code, event.exc.info);
  ADDRINT exc_ip = PIN_GetPhysicalContextReg(ctxt, REG_INST_PTR);
  if ( event.ea != exc_ip )
  {
    MSG("ExceptionAddress(%p) differs from ExceptionEIP (%p)!!!\n", (void *)addr_t(event.ea), (void *)exc_ip);
  }

  tdata->set_excp_handled(false);
  suspend_at_event(event);
  app_wait(&run_app_sem);
  tdata->drop_ctx_regs();
  if ( tdata->excp_handled() )
  {
    MSG("Continue execution after internal exception\n");
    return EHR_HANDLED;
  }
  else
  {
    MSG("Execute default system procedure for internal exception\n");
    return EHR_CONTINUE_SEARCH;
  }
}

//--------------------------------------------------------------------------
// serve requests synchronously in case the listener thread not started yet
static bool serve_sync(void)
{
  while ( true )
  {
    {
      janitor_for_pinlock_t process_state_guard(&process_state_lock);
      if ( process_detached() || process_exiting() )
        return false;
      if ( !(process_pause() || process_suspended()) )
        break;
    }
    janitor_for_pinlock_t listener_state_guard(&listener_lock);
    if ( listener_ready )
    {
      // listener thread already started - all requests will be processed by it
      break;
    }
    if ( !read_handle_packet() )
      return false;
  }
  return true;
}

//--------------------------------------------------------------------------
// separate internal thread for asynchronous IDA requests serving
static VOID ida_pin_listener(VOID *)
{
  MSG("Listener started (thread = %d)\n", thread_data_t::get_thread_id());

  {
    janitor_for_pinlock_t listener_state_guard(&listener_lock);
    listener_ready = true;
  }

  while ( true )
  {
    DEBUG(4, "Handling events in ida_pin_listener\n");
    read_handle_packet();
    if ( process_detached() )
    {
      MSG("Detached\n");
      pin_closesocket(cli_socket);
      // possible reattach?
#ifdef TRY_TO_SUPPORT_REATTACH
      if ( !accept_conn() )
        break;
      MSG("New connection accepted\n");
      process_state = APP_STATE_RUNNING;
      break_at_next_inst = true;
      instrumenter_t::init_instrumentations();
#else
      pin_closesocket(srv_socket);
      break;
#endif
    }
    if ( PIN_IsProcessExiting() )
    {
      DEBUG(2, "PIN_IsProcessExiting() -> Ok...\n");
      if ( events.empty() && process_exiting() )
      {
        MSG("Process is exiting...\n");
        break;
      }
    }
  }
  MSG("Listener exited\n");
}

//--------------------------------------------------------------------------
static void handle_start_process(void)
{
  if ( PIN_IsAttaching() )
    break_at_next_inst = true;

  // initialized stuff
  breakpoints.prepare_resume();
  instrumenter_t::init_instrumentations();

  // Initialize the semaphore used for the whole application pausing
  PIN_SemaphoreInit(&run_app_sem);
  sema_set(&run_app_sem);

  PIN_InitLock(&listener_lock);

  events.init();

  // Register image_load_cb to be called when an image is loaded
  IMG_AddInstrumentFunction(image_load_cb, 0);

  // Register image_unload_cb to be called when an image is unloaded
  IMG_AddUnloadFunction(image_unload_cb, 0);

  // Register callbacks to be called when a thread begins/ends
  PIN_AddThreadStartFunction(thread_start_cb, 0);
  PIN_AddThreadFiniFunction(thread_fini_cb, 0);

  // Register fini_cb to be called when the application exits
  PIN_AddFiniUnlockedFunction(fini_cb, 0);

  // Register aplication start callback
  PIN_AddApplicationStartFunction(app_start_cb, 0);

  // Register context change function
  PIN_AddContextChangeFunction(context_change_cb, 0);

  // Register PIN exception callback
  PIN_AddInternalExceptionHandler(internal_excp_cb, 0);

  // Create the thread for communicating with IDA
  THREADID thread_id = PIN_SpawnInternalThread(ida_pin_listener, NULL, 0, &listener_uid);
  if ( thread_id == INVALID_THREADID )
  {
    MSG("PIN_SpawnInternalThread(listener) failed\n");
    exit(-1);
  }

  if ( !instrumenter_t::init() )
    exit(-1);

  // Start the program, never returns
  PIN_StartProgram();
}

//--------------------------------------------------------------------------
static void add_segment(
  pin_meminfo_vec_t &miv,
  ADDRINT sec_ea,
  pin_memory_info_t &mi)
{
  bool added = false;
  pin_meminfo_vec_t::reverse_iterator p;
  for ( p = miv.rbegin(); p != miv.rend(); ++p )
  {
    const pin_memory_info_t &pmi = *p;

    // ignore duplicated segments
    if ( pmi.startEA == sec_ea )
      return;

    // if we found the correct position insert it
    if ( pmi.endEA <= sec_ea )
    {
      added = true;
      miv.insert(p.base(), mi);
      break;
    }
  }

  // no position found, put in the end of the list
  if ( !added )
    miv.push_back(mi);
}

#ifdef _WIN32

//--------------------------------------------------------------------------
// In win32, if we try to enumerate the segments of the application we will
// read the PIN's segments; that's: we're going to mix the application's own
// segments with the conflicting real PIN segments (the areas can overlap) so,
// at least to be able to see the referenced memory in stack and heap and other
// areas we cannot list we create 2 big segments at start and at the end.
static void get_os_segments(
        pin_meminfo_vec_t &miv,
        ADDRINT img_min_ea,
        ADDRINT img_max_ea)
{
  WINDOWS::SYSTEM_INFO si;
  WINDOWS::GetSystemInfo(&si);

  pin_memory_info_t mi;
  mi.startEA = (ADDRINT)si.lpMinimumApplicationAddress;
  mi.endEA = img_min_ea;
  mi.bitness = BITNESS;
  mi.name_size = 0;
  memset(mi.name, '\0', sizeof(mi.name));
  mi.perm = SEGPERM_READ | SEGPERM_WRITE | SEGPERM_EXEC;
  miv.insert(miv.begin(), mi);

  pin_memory_info_t mi2;
  mi2.startEA = img_max_ea;
  mi2.endEA = (ADDRINT)si.lpMaximumApplicationAddress;
  mi2.bitness = BITNESS;
  mi2.name_size = 0;
  memset(mi2.name, '\0', sizeof(mi2.name));
  mi.perm = SEGPERM_READ | SEGPERM_WRITE | SEGPERM_EXEC;
  miv.push_back(mi2);
}
#else

#ifdef __linux__

//--------------------------------------------------------------------------
const char *skip_spaces(const char *ptr)
{
  if ( ptr != NULL )
  {
    while ( isspace(*ptr) )
      ptr++;
  }
  return ptr;
}

//--------------------------------------------------------------------------
struct mapfp_entry_t
{
  addr_t ea1;
  addr_t ea2;
  addr_t offset;
  uint64 inode;
  char perm[8];
  char device[8];
  string fname;
};

//--------------------------------------------------------------------------
static bool read_mapping(FILE *mapfp, mapfp_entry_t *me)
{
  char line[2*MAXSTR];
  if ( !fgets(line, sizeof(line), mapfp) )
    return false;

  me->ea1 = BADADDR;

  uint32 len = 0;
  int code = sscanf(line, HEX_FMT"-"HEX_FMT" %s "HEX_FMT" %s " HEX64T_FMT "x%n",
                     &me->ea1,
                     &me->ea2,
                     me->perm,
                     &me->offset,
                     me->device,
                     &me->inode,
                     &len);
  if ( code == 6 && len < sizeof(line) )
  {
    char *ptr = &line[len];
    ptr = (char *)skip_spaces(ptr);
    // remove trailing spaces and eventual (deleted) suffix
    static const char delsuff[] = " (deleted)";
    const int suflen = sizeof(delsuff) - 1;
    char *end = (char*)tail(ptr);
    while ( end > ptr && isspace(end[-1]) )
      *--end = '\0';
    if ( end-ptr > suflen && strncmp(end-suflen, delsuff, suflen) == 0 )
      end[-suflen] = '\0';
    me->fname = ptr;
  }
  return (signed)me->ea1 != BADADDR;
}

//--------------------------------------------------------------------------
static void get_os_segments(pin_meminfo_vec_t &miv, ADDRINT, ADDRINT)
{
  FILE *mapfp = fopen("/proc/self/maps", "rb");
  mapfp_entry_t me;
  while ( read_mapping(mapfp, &me) )
  {
    // for some reason linux lists some areas twice
    // ignore them
    size_t i;
    for ( i=0; i < miv.size(); i++ )
      if ( miv[i].startEA == me.ea1 )
        break;
    if ( i != miv.size() )
      continue;

    // do we really want to hide the PIN's segments? I guess yes, but...
    if ( me.fname != "pinbin" )
    {
      pin_memory_info_t mi;
      mi.startEA = me.ea1;
      mi.endEA   = me.ea2;
      pin_strncpy(mi.name, me.fname.c_str(), sizeof(mi.name));
      mi.name_size = me.fname.size();
      if ( mi.name_size > sizeof(mi.name) )
        mi.name_size = sizeof(mi.name);
      mi.bitness = BITNESS;

      if ( strchr(me.perm, 'r') != NULL ) mi.perm |= SEGPERM_READ;
      if ( strchr(me.perm, 'w') != NULL ) mi.perm |= SEGPERM_WRITE;
      if ( strchr(me.perm, 'x') != NULL ) mi.perm |= SEGPERM_EXEC;

      add_segment(miv, me.ea1, mi);
    }
  }
}

#else
// MacOSX
static void get_os_segments(pin_meminfo_vec_t &, ADDRINT, ADDRINT){}
#endif

#endif

//--------------------------------------------------------------------------
static bool handle_memory_info(void)
{
  bool ret = false;

  // Visit every loaded image and fill miv vector
  pin_meminfo_vec_t miv;
  ADDRINT img_min_ea = 0;
  ADDRINT img_max_ea = 0;
  for( IMG img= APP_ImgHead(); IMG_Valid(img); img = IMG_Next(img) )
  {
    for( SEC sec= IMG_SecHead(img); SEC_Valid(sec); sec = SEC_Next(sec) )
    {
      pin_memory_info_t mi;
      ea_t sec_ea = SEC_Address(sec);
      if ( sec_ea != 0 )
      {
        mi.startEA = sec_ea;
        mi.endEA   = sec_ea + SEC_Size(sec);

        if ( img_min_ea == 0 || img_min_ea > sec_ea )
          img_min_ea = sec_ea;

        if ( img_max_ea == 0 || img_max_ea < mi.endEA )
          img_max_ea = mi.endEA;

        string sec_name;
        sec_name = IMG_Name(img) + ":" + SEC_Name(sec);
        memset(mi.name, '\0', sizeof(mi.name));
        pin_strncpy(mi.name, sec_name.c_str(), sizeof(mi.name));
        mi.name_size = (uint32)sec_name.size();
        if ( mi.name_size > sizeof(mi.name) )
          mi.name_size = sizeof(mi.name);
        mi.bitness = BITNESS;

        mi.perm = 0;
        if ( SEC_IsReadable(sec) )
          mi.perm |= SEGPERM_READ;
        if ( SEC_IsWriteable(sec) )
          mi.perm |= SEGPERM_WRITE;
        if ( SEC_IsExecutable(sec) )
          mi.perm |= SEGPERM_EXEC;

        add_segment(miv, sec_ea, mi);
        //fprintf(stderr, "Segment %s Start 0x"HEX_FMT" End 0x"HEX_FMT"\n", mi.name, mi.startEA, mi.endEA);
      }
    }
  }

  get_os_segments(miv, img_min_ea, img_max_ea);

  memimages_pkt_t pkt(PTT_MEMORY_INFO, (uint32)miv.size());

  // send a packet with the number of segments
  if ( send_packet(&pkt, sizeof(pkt), NULL, 0, "handle_memory_info(1)") )
  {
    ret = true;

    // and, then, send the information for all images
    pin_meminfo_vec_t::iterator p;
    for ( p = miv.begin(); p != miv.end(); ++p )
    {
      pin_memory_info_t &mi = *p;
      if ( !send_packet(&mi, sizeof(mi), NULL, 0, "handle_memory_info(2)") )
      {
        ret = false;
        break;
      }
    }
  }

  return ret;
}

//--------------------------------------------------------------------------
static bool handle_read_memory(ADDRINT ea, pin_size_t size)
{
  DEBUG(2, "Reading %d bytes at address %p\n", size, (void*)ea);

  idamem_response_pkt_t pkt;
  // read the data asked by IDA
  size_t copy_size = size < sizeof(pkt.buf) ? size : sizeof(pkt.buf);
  ssize_t read_bytes = PIN_SafeCopy(pkt.buf, (void*)ea, copy_size);
  pkt.size = (uint32)read_bytes;
  pkt.code = PTT_READ_MEMORY;

  ssize_t bytes = pin_send(cli_socket, &pkt, sizeof(pkt), __FUNCTION__);
  return bytes == sizeof(pkt);
}

//--------------------------------------------------------------------------
static bool handle_read_trace(void)
{
  idatrace_events_t trc_events;
  instrumenter_t::get_trace_events(&trc_events);
  trc_events.code = PTT_ACK;
  ssize_t bytes = pin_send(cli_socket, &trc_events, sizeof(trc_events), __FUNCTION__);
  return bytes == sizeof(trc_events);
}

//--------------------------------------------------------------------------
static bool handle_read_regs(THREADID tid)
{
  idapin_registers_t regs;
  thread_data_t *tdata = thread_data_t::get_thread_data(tid);
  tdata->export_ctx(&regs);
  DEBUG(2, "get_context_regs(%d): ip = %p)\n", int(tid), (void *)addr_t(regs.eip));
  ssize_t bytes = pin_send(cli_socket, &regs, sizeof(regs), __FUNCTION__);
  return bytes == sizeof(regs);
}

//--------------------------------------------------------------------------
static bool handle_limits(void)
{
  bool ret = false;
  idalimits_packet_t ans;
  ssize_t bytes = pin_recv(cli_socket, &ans, sizeof(ans), __FUNCTION__);
  idapin_packet_t res;
  if ( bytes == sizeof(ans) )
  {
    if ( !instrumenter_t::set_limits(ans.only_new,
                                     ans.trace_limit, ans.image_name) )
    {
      res.code = PTT_ERROR;
    }
    else
    {
      res.code = PTT_ACK;
    }

    // send the answer and terminate the application if the selected configuration
    // is not supported
    bytes = pin_send(cli_socket, &res, sizeof(res), __FUNCTION__);
    if ( res.code == PTT_ERROR || bytes != sizeof(res) )
    {
      MSG("Unsupported configuration or network error while setting limits, calling PIN_ExitApplication\n");
      PIN_ExitApplication(-1);
    }
    ret = true;
  }
  return ret;
}

//--------------------------------------------------------------------------
static inline void prepare_pause()
{
  pin_debug_event_t lastev;
  if ( events.back(&lastev) )
  {
    DEBUG(2, "prepare_pause: already have events - just generate SUSPEND event\n");
    // generate SUSPEND event with ea/tid of the last stored event
    emit_suspend_ev(PROCESS_SUSPEND, lastev.ea, lastev.tid);
  }
  else
  {
    DEBUG(2, "Use semaphores inside control_cb to suspend process\n");
    janitor_for_pinlock_t process_state_guard(&process_state_lock);
    if ( process_state == APP_STATE_RUNNING )
    {
      if ( thread_data_t::have_suspended_threads() )
      {
        // have at least one suspended thread: generate SUSPEND event with
        // undefined ea/tid (tid=NO_THREAD) and set state to 'suspended'.
        // Later pop_debug_event will correct this fields using
        // context of an arbitrary suspended thread
        DEBUG(2, "prepare_pause: already have suspended threads - generate SUSPEND event\n");
        emit_suspend_ev(PROCESS_SUSPEND, BADADDR, NO_THREAD);
        do_suspend_nolock(APP_STATE_SUSPENDED);
      }
      else
      {
        // tell breakpoint manager to suspend application threads as soon as it can
        breakpoints.prepare_suspend();
        process_state = APP_STATE_PAUSE;
      }
    }
  }
}

//--------------------------------------------------------------------------
// We expect IDA sends RESUME request as a response to every event
// The following function performs buffered resume:
// we do actual resume only when the event queue becomes empty
static bool do_resume(idapin_packet_t *ans, const idapin_packet_t &request)
{
  if ( thread_data_t::all_threads_suspended() )
  {
    MSG("Can't resume: all threads are suspended\n");
    ans->code = PTT_ERROR;
    return send_packet(ans, sizeof(idapin_packet_t), NULL, 0, __FUNCTION__);
  }
  pin_event_id_t eid = pin_event_id_t(request.data);
  {
    pin_debug_event_t last_ev;
    events.last_ev(&last_ev);
    if ( pin_event_id_t(last_ev.eid) != eid )
      MSG("Unexpected resume: eid=%x (%x expected)\n", eid, int(last_ev.eid));
    if ( eid == EXCEPTION )
    {
      // examine request.size field: should exception be passed to application?
      THREADID tid_local = thread_data_t::get_local_thread_id(last_ev.tid);
      thread_data_t *tdata = thread_data_t::get_thread_data(tid_local);
      if ( tdata != NULL )
        tdata->set_excp_handled(request.size != 0);
      else
        MSG("RESUME error: can't find thread data for %d\n", last_ev.tid);
    }
    janitor_for_pinlock_t process_state_guard(&process_state_lock);
    if ( events.empty() )
    {
      DEBUG(2, "Event queue is empty, do actual resume\n");

      if ( process_suspended() )
      {
        process_state_t old_state = process_state;
        process_state = APP_STATE_RUNNING;
        if ( breakpoints.prepare_resume() )
          instrumenter_t::reinit_instrumentations();
        if ( old_state != APP_STATE_WAIT_FLUSH )
          sema_set(&run_app_sem);
      }
    }
    else
    {
      DEBUG(2, "%d event(s) left in the queue, do not resume\n", int(events.size()));
    }
    if ( eid == PROCESS_EXIT )
      process_state = APP_STATE_EXITING;

    if ( eid == THREAD_EXIT )
    {
      // we had to keep thread context until THREAD_EXIT event is processed
      // by the client. Now we can release it
      THREADID tid_local = thread_data_t::get_local_thread_id(last_ev.tid);
      thread_data_t::release_thread_data(tid_local);
    }
  }
  instrumenter_t::resume();
  ans->code = PTT_ACK;
  return send_packet(ans, sizeof(idapin_packet_t), NULL, 0, __FUNCTION__);
}

//--------------------------------------------------------------------------
static bool handle_packet(const idapin_packet_t *res)
{
  bool ret = false;
  idapin_packet_t ans;
  ans.size = 0;
  ans.code = PTT_ERROR;

  if ( res->code > PTT_END )
  {
    MSG("Unknown packet type %d\n", res->code);
    return false;
  }

  if ( strcmp(last_packet, "READ EVENT") != 0 || strcmp(packet_names[res->code], last_packet) != 0 )
    DEBUG(2, "(thread %d) Handle packet(%s)\n", int(thread_data_t::get_thread_id()), packet_names[res->code]);
  last_packet = packet_names[res->code];

  switch ( res->code )
  {
    case PTT_START_PROCESS:
      // does not return
      handle_start_process();
      break;
    case PTT_EXIT_PROCESS:
      MSG("Received EXIT PROCESS, exiting from process...\n");
      // does not return
      exit_process(0);
      break;
    case PTT_DEBUG_EVENT:
      ans.data = 0;
      if ( !events.empty() && process_started() )
      {
        DEBUG(2, "Total of %d events recorded\n", (uint32)events.size());
        ans.size = (uint32)events.size();
        ans.code = PTT_DEBUG_EVENT;
      }
      else
      {
        ans.size = 0;
        ans.code = PTT_ACK;
      }
      ret = send_packet(&ans, sizeof(idapin_packet_t), NULL, 0, __FUNCTION__);
      break;
    case PTT_READ_EVENT:
      {
        pin_debug_event_t evt;
        if ( !pop_debug_event(&evt) )
          evt.eid = NO_EVENT;
        DEBUG(4, "Send event: %x\n", evt.eid);
        ret = send_packet(&evt, sizeof(evt), NULL, 0, __FUNCTION__);
      }
      break;
    case PTT_MEMORY_INFO:
      ret = handle_memory_info();
      break;
    case PTT_READ_MEMORY:
      ans.data = 0;
      ans.code = PTT_READ_MEMORY;
      ret = handle_read_memory(res->data, res->size);
      break;
    case PTT_DETACH:
      MSG("Detach request processed\n");
      ans.data = 0;
      ans.code = PTT_ACK;
      ret = send_packet(&ans, sizeof(idapin_packet_t), NULL, 0, __FUNCTION__);
      // this function is asynchronous
      detach_process();
      break;
    case PTT_PAUSE:
      // execution thread will be suspended later in control_cb()
      // here we just send ACK and set corresponding state
      DEBUG(2, "Pause request received...\n");
      ans.code = PTT_ACK;
      ret = send_packet(&ans, sizeof(idapin_packet_t), NULL, 0, __FUNCTION__);
      prepare_pause();
      MSG("Pause request processed\n");
      break;
    case PTT_RESUME:
      DEBUG(2, "Resuming after event %x\n", int(res->data));
      ret = do_resume(&ans, *res);
      break;
    case PTT_COUNT_TRACE:
      ans.code = PTT_ACK;
      ans.data = instrumenter_t::tracebuf_size();
      ret = send_packet(&ans, sizeof(idapin_packet_t), NULL, 0, __FUNCTION__);
      break;
    case PTT_READ_TRACE:
      ret = handle_read_trace();
      break;
    case PTT_CLEAR_TRACE:
      instrumenter_t::clear_trace();
      ret = true;
      break;
    case PTT_ADD_BPT:
      MSG("Adding software breakpoint at %p\n", (void *)addr_t(res->data));
      breakpoints.add_soft_bpt(ADDRINT(res->data));
      ans.code = PTT_ACK;
      ret = send_packet(&ans, sizeof(idapin_packet_t), NULL, 0, __FUNCTION__);
      break;
    case PTT_DEL_BPT:
      MSG("Remove software breakpoint at %p\n", (void *)addr_t(res->data));
      breakpoints.del_soft_bpt(ADDRINT(res->data));
      ans.code = PTT_ACK;
      ret = send_packet(&ans, sizeof(idapin_packet_t), NULL, 0, __FUNCTION__);
      break;
    case PTT_CAN_READ_REGS:
      {
        THREADID tid_local = thread_data_t::get_local_thread_id((THREADID)res->data);
        thread_data_t *tdata = thread_data_t::get_thread_data(tid_local);
        ans.code = tdata->ctx_ok() ? PTT_ACK : PTT_ERROR;
        ret = send_packet(&ans, sizeof(idapin_packet_t), NULL, 0, __FUNCTION__);
      }
      break;
    case PTT_READ_REGS:
      {
        THREADID tid = thread_data_t::get_local_thread_id((THREADID)res->data);
        ret = handle_read_regs(tid);
      }
      break;
    case PTT_SET_TRACE:
      {
        uint32 trace_types = (uint32)res->data;
        MSG("Set trace to %d\n", trace_types);
        instrumenter_t::update_instrumentation(trace_types);
        ans.code = PTT_ACK;
        ret = send_packet(&ans, sizeof(idapin_packet_t), NULL, 0, __FUNCTION__);
      }
      break;
    case PTT_SET_OPTIONS:
      ans.code = PTT_ACK;
      if ( send_packet(&ans, sizeof(idapin_packet_t), NULL, 0, __FUNCTION__) )
        ret = handle_limits();
      break;
    case PTT_STEP:
      ans.code = PTT_ACK;
      if ( send_packet(&ans, sizeof(idapin_packet_t), NULL, 0, __FUNCTION__) )
      {
        breakpoints.set_step(thread_data_t::get_local_thread_id((THREADID)res->data));
        ret = true;
      }
      break;
    case PTT_THREAD_SUSPEND:
      ans.code = PTT_ACK;
      if ( send_packet(&ans, sizeof(idapin_packet_t), NULL, 0, __FUNCTION__) )
      {
        THREADID tid = thread_data_t::get_local_thread_id((THREADID)res->data);
        thread_data_t *tdata = thread_data_t::get_thread_data(tid);
        tdata->suspend();
        ret = true;
      }
      break;
    case PTT_THREAD_RESUME:
      ans.code = PTT_ACK;
      if ( send_packet(&ans, sizeof(idapin_packet_t), NULL, 0, __FUNCTION__) )
      {
        THREADID tid = thread_data_t::get_local_thread_id((THREADID)res->data);
        thread_data_t *tdata = thread_data_t::get_thread_data(tid);
        tdata->resume();
        ret = true;
      }
      break;
    default:
      MSG("UNKNOWN PACKET RECEIVED WITH CODE %d\n", res->code);
      last_packet = "UNKNOWN " + res->code;
      break;
  }
  DEBUG(4, "LAST PACKET WAS %s\n", last_packet);
  return ret;
}

//--------------------------------------------------------------------------
static bool read_handle_packet(idapin_packet_t *res)
{
  idapin_packet_t ipack;
  if ( res == NULL )
    res = &ipack;
  DEBUG(4, "Receiving packet, expected %d bytes...\n",(uint32)sizeof(*res));
  ssize_t bytes = pin_recv(cli_socket, res, sizeof(*res), "read_handle_packet");
  if ( bytes == -1 )
  {
    error_msg("recv");
    return false;
  }

  if ( bytes == 0 )
  {
    MSG("Connection closed by peer, exiting...\n");
    exit_process(0);
  }

  if ( !handle_packet(res) )
  {
    MSG("Error handling %s packet, exiting...\n", last_packet);
    exit_process(0);
  }
  return true;
}

//--------------------------------------------------------------------------
static bool handle_packets(int total, pin_event_id_t until_ev)
{
  int packets = 0;
  while ( total == -1 || packets++ < total )
  {
    idapin_packet_t res;
    if ( !read_handle_packet(&res) )
      return false;
    if ( res.code == PTT_RESUME )
    {
      pin_event_id_t last_ev = pin_event_id_t(res.data);
      if ( until_ev != NO_EVENT && last_ev == until_ev )
      {
        MSG("Expected resume packet, received (ev=%x)\n", int(last_ev));
        break;
      }
    }
  }

  if ( total == packets )
    DEBUG(2, "Maximum number of packets reached, exiting from handle_packets...\n");
  else
    DEBUG(2, "Expected packet received, exiting from handle_packets...\n");

  return true;
}

//--------------------------------------------------------------------------
// Start communication with IDA
static bool listen_to_ida(void)
{
  // initialize the socket and connect to ida
  if ( !init_socket() )
  {
    DEBUG(2, "listen_to_ida: init_socket() failed!\n");
    return false;
  }

  MSG("CONNECTED TO IDA\n");

  // Handle the 1st packets, PTT_START_PROCESS should be one of them:
  // this request leads to installing PIN callbacks and calling
  // PIN_StartProgram() which never returns.
  // The next portion of packets (variable number, until resume to
  // PROCESS_START event) will be handled in the application start
  // callback. Then we serve packets synchronously by callback/analysis
  // routines until the separate internal thread (listener) becomes active.
  // Finally, the rest of packets will be served by the listened thread.
  bool ret = handle_packets(5);

  // normally we should never reach this point: it could happen
  // if there was no PTT_START_PROCESS request among the first 5 packets
  MSG("Exiting from listen_to_ida\n");

  return ret;
}

//--------------------------------------------------------------------------
static void open_console(void)
{
#ifdef _WIN32
  if ( WINDOWS::AllocConsole() )
  {
    freopen("CONIN$" , "rb", stdin);
    freopen("CONOUT$", "wb", stdout);
    freopen("CONOUT$", "wb", stderr);
    std::ios::sync_with_stdio();
  }
#endif
}

//--------------------------------------------------------------------------
int main(int argc, char * argv[])
{
  // Initialize pin command line
  if ( PIN_Init(argc, argv) )
  {
    MSG("PIN_Init call failed!\n");
    return usage();
  }

  int value = knob_debug_mode.Value();
  if ( value <= 0 )
  {
    const char *envval = getenv("IDAPIN_DEBUG");
    if ( envval != NULL )
      value = atoi(envval);
  }
  if ( value > 0 )
  {
    debug_level = value;
    open_console();
    MSG("IDA PIN Tool version $Revision: #114 $\nInitializing PIN tool...\n\n");
  }

  DEBUG(2, "IDA PIN Tool started (debug level=%d)\n", debug_level);
  // Connect to IDA's debugger; it only returns in case of error
  if ( !listen_to_ida() )
  {
    DEBUG(2, "listen_to_ida() failed\n");
  }

  return 0;
}

//--------------------------------------------------------------------------
// Implementation of local classes
//--------------------------------------------------------------------------
int thread_data_t::thread_cnt = 0;
int thread_data_t::suspeded_cnt = 0;
thread_data_t::thrdata_map_t thread_data_t::thr_data;
std::map <pin_thid, THREADID> thread_data_t::local_tids;
PIN_LOCK thread_data_t::thr_data_lock;
bool thread_data_t::thr_data_lock_inited = false;

//--------------------------------------------------------------------------
inline thread_data_t::thread_data_t()
  : ctx(NULL), ctx_regs(NULL), ext_tid(NO_THREAD), susp(false), ev_handled(false)
{
  PIN_SemaphoreInit(&thr_sem);
  PIN_SemaphoreSet(&thr_sem);
  PIN_InitLock(&ctx_lock);
  ++thread_cnt;
  DEBUG(2, "Thread data created (#threads=%d)\n", thread_cnt);
}

//--------------------------------------------------------------------------
inline thread_data_t::~thread_data_t()
{
  delete ctx;
  local_tids.erase(ext_tid);
  ctx_regs = NULL;
  --thread_cnt;
  DEBUG(2, "Thread data deleted (#threads=%d)\n", thread_cnt);
}

//--------------------------------------------------------------------------
inline void thread_data_t::suspend()
{
  sema_clear(&thr_sem);
  susp = true;
  ++suspeded_cnt;
}

//--------------------------------------------------------------------------
inline void thread_data_t::set_excp_handled(bool val)
{
  DEBUG(3, "thread_data_t::set_excp_handled(%d/%d)\n", ext_tid, val);
  ev_handled = val;
}

//--------------------------------------------------------------------------
inline void thread_data_t::wait()
{
  // do not suspend thread if listener thread has not started yet
  if ( listener_ready )
    sema_wait(&thr_sem);
}

//--------------------------------------------------------------------------
inline void thread_data_t::resume()
{
  susp = false;
  --suspeded_cnt;
  sema_set(&thr_sem);
}

//--------------------------------------------------------------------------
inline void thread_data_t::save_ctx(const CONTEXT *src_ctx)
{
  janitor_for_pinlock_t plj(&ctx_lock);
  PIN_SaveContext(src_ctx, get_ctx());
  ctx_regs = NULL;
}

//--------------------------------------------------------------------------
inline void thread_data_t::save_ctx_regs(const idapin_registers_t *src_ctx_regs)
{
  janitor_for_pinlock_t plj(&ctx_lock);
  ctx_regs = src_ctx_regs;
}

//--------------------------------------------------------------------------
// invalidate saved registers
inline void thread_data_t::drop_ctx_regs()
{
  janitor_for_pinlock_t plj(&ctx_lock);
  ctx_regs = NULL;
}

//--------------------------------------------------------------------------
inline void thread_data_t::export_ctx(idapin_registers_t *regs)
{
  janitor_for_pinlock_t plj(&ctx_lock);
  if ( ctx_regs != NULL )
    *regs = *ctx_regs;
  else
    get_context_regs(ctx, regs);
}

//--------------------------------------------------------------------------
inline thread_data_t *thread_data_t::get_thread_data()
{
  return get_thread_data(get_thread_id());
}

//--------------------------------------------------------------------------
inline thread_data_t *thread_data_t::get_thread_data(THREADID tid)
{
  if ( !thr_data_lock_inited )
  {
    PIN_InitLock(&thr_data_lock);
    thr_data_lock_inited = true;
  }
  janitor_for_pinlock_t plj(&thr_data_lock);
  thrdata_map_t::iterator it = thr_data.find(tid);
  thread_data_t *tdata;
  if ( it != thr_data.end() )
  {
    tdata = it->second;
  }
  else
  {
    MSG("Created thread data (%d)\n", tid);
    tdata = new thread_data_t;
    thr_data[tid] = tdata;
  }
  tdata->try_init_ext_tid(tid);
  return tdata;
}

//--------------------------------------------------------------------------
inline thread_data_t *thread_data_t::get_any_stopped_thread()
{
  for ( thrdata_map_t::iterator p = thr_data.begin();
        p != thr_data.end(); ++p )
  {
    if ( p->second->suspended() )
      return p->second;
  }
  return NULL;
}

//--------------------------------------------------------------------------
inline bool thread_data_t::release_thread_data(THREADID tid)
{
  janitor_for_pinlock_t plj(&thr_data_lock);
  thrdata_map_t::iterator it = thr_data.find(tid);
  if ( it == thr_data.end() )
    return false;
  delete it->second;
  thr_data.erase(it);
  return true;
}

//--------------------------------------------------------------------------
inline CONTEXT *thread_data_t::get_thread_context(THREADID tid)
{
  thread_data_t *tdata = get_thread_data(tid);
  return tdata->get_ctx();
}

//--------------------------------------------------------------------------
inline THREADID thread_data_t::get_thread_id()
{
  return PIN_ThreadId();
}

//--------------------------------------------------------------------------
// There is no way to get external (OS-specific) thread id directly by local id.
// So we assume the control is inside the same thread here (as should be normaly).
// If it's not so - left external id undefined in hope to be more lucky later.
inline void thread_data_t::try_init_ext_tid(THREADID local_tid)
{
  if ( ext_tid == NO_THREAD )
  {
    if ( local_tid == get_thread_id() )
      set_ext_tid(local_tid, PIN_GetTid());
    else
      MSG("try_init_ext_tid(%d) failed inside %d\n", int(local_tid), int(get_thread_id()));
  }
}

//--------------------------------------------------------------------------
inline void thread_data_t::set_ext_tid(THREADID local_tid, pin_thid tid)
{
  ext_tid = tid;
  local_tids[tid] = local_tid;
}

//--------------------------------------------------------------------------
inline pin_thid thread_data_t::get_ext_thread_id(THREADID local_tid)
{
  thread_data_t *tdata = get_thread_data(local_tid);
  return tdata==NULL ? NO_THREAD : tdata->ext_tid;
}

//--------------------------------------------------------------------------
inline THREADID thread_data_t::get_local_thread_id(pin_thid tid_ext)
{
  std::map <pin_thid, THREADID>::iterator it = local_tids.find(tid_ext);
  return it==local_tids.end() ? INVALID_THREADID: it->second;
}

//--------------------------------------------------------------------------
ev_queue_t::ev_queue_t()
{
  init();
}

//--------------------------------------------------------------------------
void ev_queue_t::init()
{
  queue.clear();
  PIN_InitLock(&lock);
  last_retrieved_ev.eid = NO_EVENT;
}

//--------------------------------------------------------------------------
ev_queue_t::~ev_queue_t()
{
}

//--------------------------------------------------------------------------
inline void ev_queue_t::push_back(const pin_debug_event_t &ev)
{
  add_ev(ev, false);
}

//--------------------------------------------------------------------------
inline void ev_queue_t::push_front(const pin_debug_event_t &ev)
{
  add_ev(ev, true);
}

//--------------------------------------------------------------------------
inline bool ev_queue_t::pop_front(pin_debug_event_t *out_ev)
{
  janitor_for_pinlock_t ql_guard(&lock);
  if ( !queue.empty() )
  {
    *out_ev = queue.front();
    last_retrieved_ev = *out_ev;
    queue.pop_front();
    return true;
  }
  return false;
}

//--------------------------------------------------------------------------
inline void ev_queue_t::last_ev(pin_debug_event_t *out_ev)
{
  janitor_for_pinlock_t ql_guard(&lock);
  *out_ev = last_retrieved_ev;
}

//--------------------------------------------------------------------------
inline bool ev_queue_t::back(pin_debug_event_t *out_ev)
{
  janitor_for_pinlock_t ql_guard(&lock);
  if ( !queue.empty() )
  {
    *out_ev = queue.back();
    return true;
  }
  return false;
}

//--------------------------------------------------------------------------
inline size_t ev_queue_t::size()
{
  janitor_for_pinlock_t ql_guard(&lock);
  return queue.size();
}

//--------------------------------------------------------------------------
inline bool ev_queue_t::empty()
{
  return size() == 0;
}

//--------------------------------------------------------------------------
inline void ev_queue_t::add_ev(const pin_debug_event_t &ev, bool front)
{
  DEBUG(3, "ev_queue_t::add_ev %x\n", int(ev.eid));
  janitor_for_pinlock_t ql_guard(&lock);
  if ( front )
    queue.push_front(ev);
  else
    queue.push_back(ev);
  DEBUG(3, "ev_queue_t::add_ev ended\n");
}

//--------------------------------------------------------------------------
bool bpt_mgr_t::control_enabled = false;
//--------------------------------------------------------------------------
bpt_mgr_t::bpt_mgr_t()
{
  cleanup();
}

//--------------------------------------------------------------------------
bpt_mgr_t::~bpt_mgr_t()
{
  cleanup();
}

//--------------------------------------------------------------------------
void bpt_mgr_t::cleanup()
{
  bpts.clear();
  pending_bpts.clear();
  stepping_thread = INVALID_THREADID;
  need_reinst = false;
  PIN_InitLock(&bpt_lock);
}

//--------------------------------------------------------------------------
inline void bpt_mgr_t::add_soft_bpt(ADDRINT at)
{
  janitor_for_pinlock_t plj(&bpt_lock);
  addrset_t::iterator p = bpts.find(at);
  if ( p != bpts.end() )
    return;
  addrset_t::iterator pp = pending_bpts.find(at);
  if ( pp == pending_bpts.end() )
  {
    DEBUG(2, "bpt_mgr_t::add_soft_bpt(%p)\n", (void *)at);
    pending_bpts.insert(at);
    need_reinst = true;
  }
}

//--------------------------------------------------------------------------
inline void bpt_mgr_t::del_soft_bpt(ADDRINT at)
{
  janitor_for_pinlock_t plj(&bpt_lock);
  addrset_t::iterator p = bpts.find(at);
  if ( p != bpts.end() )
  {
    DEBUG(2, "bpt_mgr_t::del_soft_bpt(%p, installed)\n", (void *)at);
    bpts.erase(p);
    need_reinst = true;
    return;
  }
  addrset_t::iterator pp = pending_bpts.find(at);
  if ( pp != pending_bpts.end() )
  {
    DEBUG(2, "bpt_mgr_t::del_soft_bpt(%p, pending)\n", (void *)at);
    pending_bpts.erase(pp);
    need_reinst = true;
  }
}

//--------------------------------------------------------------------------
inline bool bpt_mgr_t::have_bpt_at(ADDRINT addr)
{
  janitor_for_pinlock_t plj(&bpt_lock);
  return have_bpt_at_nolock(addr);
}

//--------------------------------------------------------------------------
inline bool bpt_mgr_t::have_bpt_at_nolock(ADDRINT addr)
{
  addrset_t::iterator p = bpts.find(addr);
  return p != bpts.end();
}

//--------------------------------------------------------------------------
inline void bpt_mgr_t::set_step(THREADID stepping_tid)
{
  janitor_for_pinlock_t plj(&bpt_lock);
  DEBUG(2, "bpt_mgr_t::set_step(tid=%d)\n", int(stepping_tid));
  stepping_thread = stepping_tid;
}

//--------------------------------------------------------------------------
bool bpt_mgr_t::prepare_resume()
{
  janitor_for_pinlock_t plj(&bpt_lock);
  update_ctrl_flag();
  bool ret = need_reinst;
  need_reinst = false;
  DEBUG(2, "bpt_mgr_t::prepare_resume -> (control_enabled=%d) %d\n", control_enabled, int(ret));
  return ret;
}

//--------------------------------------------------------------------------
inline bool bpt_mgr_t::need_control_cb() const
{
  return stepping_thread != INVALID_THREADID
      || break_at_next_inst
      || thread_data_t::have_suspended_threads()
      || !pending_bpts.empty();
}

//--------------------------------------------------------------------------
inline void bpt_mgr_t::update_ctrl_flag() const
{
  control_enabled = need_control_cb();
}

//--------------------------------------------------------------------------
// prepare suspend (don't acquire process_state_lock, it must be done by caller)
void bpt_mgr_t::prepare_suspend()
{
  if ( process_detached() || process_exiting() )
  {
    DEBUG(2, "bpt_mgr_t::prepare_suspend: detached/exiting - don't suspend\n");
  }
  else
  {
    DEBUG(2, "bpt_mgr_t::prepare_suspend\n");
    janitor_for_pinlock_t plj(&bpt_lock);
    control_enabled = true;
  }
}

//--------------------------------------------------------------------------
//lint -e{1746} parameter 'ins' could be made const reference
void bpt_mgr_t::add_rtns(INS ins, ADDRINT ins_addr)
{
  DEBUG(3, "bpt_mgr_t::add_rtns (%p) -> %d\n", (void *)ins_addr, int(control_enabled));
  // add the real instruction instrumentation
  INS_InsertIfCall(ins, IPOINT_BEFORE, (AFUNPTR)ctrl_rtn_enabled,
                   IARG_FAST_ANALYSIS_CALL,
                   IARG_CALL_ORDER, CALL_ORDER_FIRST,
                   IARG_END);
  INS_InsertThenCall(ins, IPOINT_BEFORE, (AFUNPTR)ctrl_rtn,
                   IARG_FAST_ANALYSIS_CALL,
                   IARG_CALL_ORDER, CALL_ORDER_FIRST,
                   IARG_INST_PTR, IARG_CONST_CONTEXT, IARG_END);

  janitor_for_pinlock_t plj(&bpt_lock);
  bool have_bpt;
  if ( stepping_thread != INVALID_THREADID
    || thread_data_t::have_suspended_threads()
    || !instrumenter_t::instr_state_ok() )
  {
    // reinstrumented did not start really or
    // ctrl_rtn is active anyway so we will process pending breakpoints here
    addrset_t::iterator p = pending_bpts.find(ins_addr);
    if ( p != pending_bpts.end() )
    {
      pending_bpts.erase(p);
      bpts.insert(ins_addr);
      have_bpt = true;
      update_ctrl_flag();
      DEBUG(2, "Inject pending bpt at (%p), npending=%d, ctrl_clag=%d\n", (void *)ins_addr, int(pending_bpts.size()), control_enabled);

    }
    else
    {
      have_bpt = have_bpt_at_nolock(ins_addr);
    }
  }
  else
  {
    // we are called, instrumenter state is Ok, so can assume jit cache has been
    // already cleaned and we can remove (move to permanent set) pending bpts
    // and recalculate ctrl_flag to deactivate ctrl_rtn as soon as possible
    addrset_t::iterator p = pending_bpts.begin();
    if ( p != pending_bpts.end() )
    {
      DEBUG(2, "Move %d pending breakpoints to permanent set\n",
                                      int(pending_bpts.size()));
      for ( ; p != pending_bpts.end(); ++p )
        bpts.insert(*p);
      pending_bpts.clear();
      update_ctrl_flag();
    }
    have_bpt = have_bpt_at_nolock(ins_addr);
  }
  if ( have_bpt )
  {
    DEBUG(2, "bpt_mgr_t::add_bpt_rtn (%p)\n", (void *)ins_addr);
    INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)bpt_rtn,
                     IARG_FAST_ANALYSIS_CALL,
                     IARG_CALL_ORDER, CALL_ORDER_FIRST + 1,
                     IARG_INST_PTR, IARG_CONST_CONTEXT, IARG_END);
  }
}

//--------------------------------------------------------------------------
ADDRINT bpt_mgr_t::ctrl_rtn_enabled()
{
  return control_enabled;
}

//--------------------------------------------------------------------------
void PIN_FAST_ANALYSIS_CALL bpt_mgr_t::ctrl_rtn(ADDRINT addr, const CONTEXT *ctx)
{
  breakpoints.do_ctrl(addr, ctx);
}

//--------------------------------------------------------------------------
inline void bpt_mgr_t::do_ctrl(ADDRINT addr, const CONTEXT *ctx)
{
  if ( process_exiting() )
    return;

  THREADID tid_local = thread_data_t::get_thread_id();
  thread_data_t *tdata = thread_data_t::get_thread_data(tid_local);

  DEBUG(3, "bpt_mgr_t::do_ctrl at %p (thread %d)\n", (void*)addr, int(tid_local));

  // save the current thread's context if the process is to be suspended
  tdata->save_ctx(ctx);

  // now process forthcoming stepping/pause if any
  // do nothing if the listener thread is not started yet
  ev_id_t eid = EV_NO_EVENT;
  {
    janitor_for_pinlock_t plj(&bpt_lock);
    if ( pending_bpts.find(addr) != pending_bpts.end() )
    {
      eid = EV_BPT;
      DEBUG(2, "Pending bpt at %p (thread %d)\n", (void*)addr, int(tid_local));
    }
    else
    {
      if ( stepping_thread == tid_local )
      {
        if ( !have_bpt_at_nolock(addr) )
          eid = EV_SINGLE_STEP;
      }
      else
      {
        if ( break_at_next_inst )
        {
          // emit event only if there is no bpt at this address, otherwise
          // bpreakpoint will be emited by bpt_rtn
          if ( !have_bpt_at_nolock(addr) )
            eid = EV_INITIAL_STOP;
        }
      }
    }
  }

  {
    janitor_for_pinlock_t process_state_guard(&process_state_lock);

    if ( eid == EV_NO_EVENT && process_pause() )
      eid = EV_PAUSED;

    emit_event(eid, addr, tid_local);
  }

  // suspend thread if needed
  tdata->wait();
  app_wait(&run_app_sem);
}

//--------------------------------------------------------------------------
void PIN_FAST_ANALYSIS_CALL bpt_mgr_t::bpt_rtn(ADDRINT addr, const CONTEXT *ctx)
{
  breakpoints.do_bpt(addr, ctx);
}

//--------------------------------------------------------------------------
inline void bpt_mgr_t::do_bpt(ADDRINT addr, const CONTEXT *ctx)
{
  if ( process_exiting() )
    return;

  THREADID tid_local = thread_data_t::get_thread_id();
  thread_data_t *tdata = thread_data_t::get_thread_data(tid_local);

  DEBUG(2, "bpt_mgr_t::do_bpt at %p (thread %d)\n", (void*)addr, int(tid_local));

  // save the current thread's context if the process is to be suspended
  tdata->save_ctx(ctx);

  // now process the breakpoint if it really exists
  {
    janitor_for_pinlock_t process_state_guard(&process_state_lock);
    if ( have_bpt_at(addr) )
    {
      emit_event(EV_BPT, addr, tid_local);
    }
  }

  // suspend thread if needed
  tdata->wait();
  app_wait(&run_app_sem);
}

//--------------------------------------------------------------------------
// caller should acquire process_state_lock when calling this function
void bpt_mgr_t::emit_event(ev_id_t eid, ADDRINT addr, THREADID tid)
{
  struct bpt_ev_t
  {
    const char *name;
    pin_event_id_t id;
  };
  static const bpt_ev_t bpt_evs[] =
  {
    { "Paused",        PROCESS_SUSPEND },
    { "Single step",   STEP },
    { "Breakpoint",    BREAKPOINT },
    { "Initial break", PROCESS_ATTACH }
  };
  if ( eid != EV_NO_EVENT && !process_detached() && !process_exiting() )
  {
    {
      janitor_for_pinlock_t plj(&bpt_lock);
      break_at_next_inst = false;
      stepping_thread = INVALID_THREADID;
    }
    do_suspend_nolock(APP_STATE_SUSPENDED);

    pin_thid ext_tid = thread_data_t::get_ext_thread_id(tid);
    MSG("%s at %p (thread %d/%d)\n", bpt_evs[eid].name, (void*)addr, int(ext_tid), int(tid));

    emit_suspend_ev(bpt_evs[eid].id, addr, ext_tid);
  }
}

//--------------------------------------------------------------------------
// different trace modes (used by IF-routines)
bool instrumenter_t::tracing_instruction = true;
bool instrumenter_t::tracing_bblock      = false;
bool instrumenter_t::tracing_routine     = false;
bool instrumenter_t::tracing_registers   = false;
bool instrumenter_t::log_ret_isns        = true;

instrumenter_t::instr_state_t
instrumenter_t::state = instrumenter_t::INSTR_STATE_INITIAL;

// already enabled instrumentations (TF_TRACE_... flags)
uchar instrumenter_t::instrumentations = 0;

// trace buffer
PIN_LOCK instrumenter_t::tracebuf_lock;
instrumenter_t::trc_deque_t instrumenter_t::trace_addrs;
PIN_SEMAPHORE instrumenter_t::tracebuf_sem;
// already recorded instructions
instrumenter_t::addr_deque_t instrumenter_t::all_addrs;
// limits
bool instrumenter_t::only_new_instructions = false;
bool instrumenter_t::trace_everything = false;
uint32 instrumenter_t::enqueue_limit = 1000000;
const uint32 instrumenter_t::skip_limit = 1000000;
ADDRINT instrumenter_t::min_address = BADADDR;
ADDRINT instrumenter_t::max_address = BADADDR;
string instrumenter_t::image_name;

// flag: reinstrumenter thread actually started
bool instrumenter_t::reinstr_started = false;

#ifdef SEPARATE_THREAD_FOR_REINSTR
PIN_SEMAPHORE instrumenter_t::reinstr_sem;
PIN_THREAD_UID instrumenter_t::reinstr_uid;
#endif

//--------------------------------------------------------------------------
bool instrumenter_t::init()
{
#ifdef SEPARATE_THREAD_FOR_REINSTR
  // PIN_RemoveInstrumentation acquires vm lock - calling it when
  // a callback or analysis routine is suspended can cause deadlock
  // so create a separate thread for that
  PIN_SemaphoreInit(&reinstr_sem);
  sema_clear(&reinstr_sem);
  THREADID tid = PIN_SpawnInternalThread(reinstrumenter, NULL, 0, &reinstr_uid);
  if ( tid == INVALID_THREADID )
  {
    MSG("PIN_SpawnInternalThread(RemoveInstrumentation thread) failed\n");
    return false;
  }
#endif
  // Initialize the trace buffer semaphore
  PIN_SemaphoreInit(&tracebuf_sem);
  // And immediately set it
  sema_set(&tracebuf_sem);
  // Initialize the trace events list lock
  PIN_InitLock(&tracebuf_lock);
  return true;
}

//--------------------------------------------------------------------------
bool instrumenter_t::finish()
{
#ifdef SEPARATE_THREAD_FOR_REINSTR
  // terminate internal thread and wait for it
  sema_set(&reinstr_sem);
  return wait_for_thread_termination(reinstr_uid);
#else
  return true;
#endif
}

//--------------------------------------------------------------------------
void instrumenter_t::init_instrumentations()
{
  if ( !tracing_instruction && !tracing_bblock && !tracing_routine )
  {
    MSG("NOTICE: No tracing method selected, nothing will be recorded until some tracing method is selected.\n");
  }

  bool control_cb_enabled = breakpoints.need_control_cb();
  MSG("Init tracing/%p..%p/ "
      "%croutine%s, %cbblk, %cinstruction%s, %cregs, %cflow\n",
      (void *)(trace_everything ? 0       : min_address),
      (void *)(trace_everything ? BADADDR : max_address),
      tracing_routine       ? '+' : '-',
        (tracing_routine && log_ret_isns) ? "+retns" : "",
      tracing_bblock        ? '+' : '-',
      tracing_instruction   ? '+' : '-',
        (tracing_instruction && only_new_instructions) ? "/new only" : "",
      tracing_registers     ? '+' : '-',
      control_cb_enabled    ? '+' : '-');

  add_instrumentation(TF_TRACE_INSN);
  if ( tracing_bblock )
    add_instrumentation(TF_TRACE_BBLOCK);
  if ( tracing_routine )
    add_instrumentation(TF_TRACE_ROUTINE);
}

//--------------------------------------------------------------------------
void instrumenter_t::update_instrumentation(uint32 trace_types)
{
  bool do_reinit = (trace_types & ~TF_REGISTERS) != curr_trace_types();

  tracing_instruction = (trace_types & TF_TRACE_INSN) != 0;
  tracing_bblock = (trace_types & TF_TRACE_BBLOCK) != 0;
  tracing_routine = (trace_types & TF_TRACE_ROUTINE) != 0;
  tracing_registers = (trace_types & TF_REGISTERS) != 0;
  log_ret_isns = (trace_types & TF_LOG_RET) != 0;
  only_new_instructions = (trace_types & TF_ONLY_NEW_ISNS) != 0;
  trace_everything = (trace_types & TF_TRACE_EVERYTHING) != 0;
  if ( debug_level <= 1 )
    debug_level = ((trace_types & TF_LOGGING) != 0) ? 1 : 0;

  if ( do_reinit )
    reinit_instrumentations();
  else
    init_instrumentations();

  MSG("%sabling register values tracing...\n", tracing_registers ? "En" : "Dis");
}

//--------------------------------------------------------------------------
inline void instrumenter_t::reinit_instrumentations()
{
  MSG("Reinit instrumentations\n");

  if ( state != INSTR_STATE_INITIAL )
  {
    state = INSTR_STATE_NEED_REINIT;
#ifdef SEPARATE_THREAD_FOR_REINSTR
    if ( reinstr_started )
      sema_set(&reinstr_sem);
#else
    remove_instrumentations();
#endif
  }
  else
  {
    // first call: don't need reinistrumenting
    state = INSTR_STATE_OK;
  }
  init_instrumentations();
}

//--------------------------------------------------------------------------
inline void instrumenter_t::remove_instrumentations()
{
  state = INSTR_STATE_REINIT_STARTED;
  DEBUG(3, "PIN_RemoveInstrumentation called\n");
  PIN_RemoveInstrumentation();
  DEBUG(3, "PIN_RemoveInstrumentation ended\n");
  state = INSTR_STATE_OK;
  DEBUG(2, "JIT cache cleaned\n");
}

#ifdef SEPARATE_THREAD_FOR_REINSTR
//--------------------------------------------------------------------------
VOID instrumenter_t::reinstrumenter(VOID *)
{
  MSG("Reinstrumenter started (thread = %d)\n", thread_data_t::get_thread_id());

  reinstr_started = true;
#ifdef TRY_TO_SUPPORT_REATTACH
  while ( !process_exiting() )
#else
  while ( !(process_exiting() || process_detached()) )
#endif
  {
    if ( PIN_SemaphoreTimedWait(&reinstr_sem, 100) )
    {
      DEBUG(3, "GetVmLock\n");
      GetVmLock();
      remove_instrumentations();
      ReleaseVmLock();
      sema_clear(&reinstr_sem);
    }
  }
  MSG("Reinstrumenter exited\n");
}
#endif

//--------------------------------------------------------------------------
void instrumenter_t::add_instrumentation(trace_flags_t inst)
{
  if ( (instrumentations & inst) == 0 )
  {
    switch ( inst )
    {
      case TF_TRACE_INSN:
        // Register instruction_cb to be called to instrument instructions
        MSG("Adding instruction level instrumentation...\n");
        INS_AddInstrumentFunction(instruction_cb, 0);
        break;
      case TF_TRACE_BBLOCK:
        // Register trace_cb to be called to instrument basic blocks
        MSG("Adding trace level instrumentation...\n");
        TRACE_AddInstrumentFunction(trace_cb, 0);
        break;
      case TF_TRACE_ROUTINE:
        // Register routine_cb to be called to instrument routines
        MSG("Adding routine level instrumentation...\n");
        TRACE_AddInstrumentFunction(routine_cb, 0);
        break;
      default:
        MSG("Unknown instrumentation type %d!\n", inst);
        abort();
    }

    instrumentations |= inst;
  }
}

//--------------------------------------------------------------------------
// Pin calls this function when precompiles an application code
// every time a new instruction is encountered
//lint -e{1746} parameter 'ins' could be made const reference
VOID instrumenter_t::instruction_cb(INS ins, VOID *)
{
  ADDRINT addr = INS_Address(ins);

  if ( tracing_instruction && check_address(addr) )
  {
    // Insert a call to ins_logic_cb before every instruction
    INS_InsertIfCall(ins, IPOINT_BEFORE, (AFUNPTR)ins_enabled,
              IARG_FAST_ANALYSIS_CALL,
              IARG_CALL_ORDER, CALL_ORDER_LAST,
              IARG_INST_PTR, IARG_END);
    INS_InsertThenCall(ins, IPOINT_BEFORE, (AFUNPTR)ins_logic_cb,
              IARG_FAST_ANALYSIS_CALL,
              IARG_CALL_ORDER, CALL_ORDER_LAST,
              IARG_CONST_CONTEXT, IARG_INST_PTR,
              IARG_UINT32, tev_insn, IARG_END);
  }

  breakpoints.add_rtns(ins, addr);
}

//--------------------------------------------------------------------------
// Pin calls this function when precompiles an application code
// every time a new basic block is encountered.
VOID instrumenter_t::trace_cb(TRACE trace, VOID *)
{
  // Visit every basic block in the trace
  for ( BBL bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl) )
  {
    bool first = true;
    for ( INS ins = BBL_InsHead(bbl); INS_Valid(ins); ins = INS_Next(ins) )
    {
      ADDRINT addr = INS_Address(ins);
      if ( check_address(addr) && add_bbl_logic_cb(ins, first) )
        first = false;
    }
  }
}

//--------------------------------------------------------------------------
// Pin calls this function when precompiles an application code
// every time a new basic block is encountered *BUT*
// we will use this callback for instrumenting routines instead of using the
// routine instrumentation API offered by the toolkit
VOID instrumenter_t::routine_cb(TRACE trace, VOID *)
{
  // Visit every basic block in the trace
  for ( BBL bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl) )
  {
    for ( INS ins = BBL_InsHead(bbl); INS_Valid(ins); ins = INS_Next(ins) )
      add_rtn_logic_cb(ins);
  }
}

//--------------------------------------------------------------------------
//lint -e{1746} parameter 'ins' could be made const reference
bool instrumenter_t::add_rtn_logic_cb(INS ins)
{
  if ( tracing_routine )
  {
    // handle both calls and push + ret like in the following example:
    //
    // push offset some_func
    // retn
    //
    if ( INS_IsCall(ins) || INS_IsRet(ins) )
    {
      // add the real instruction instrumentation
      INS_InsertIfCall(ins, IPOINT_TAKEN_BRANCH,
                       (AFUNPTR)rtn_enabled, IARG_INST_PTR, IARG_END);
      INS_InsertThenCall(ins, IPOINT_TAKEN_BRANCH,
                       (AFUNPTR)rtn_logic_cb, IARG_FAST_ANALYSIS_CALL,
                       IARG_ADDRINT, INS_Address(ins),
                       IARG_BRANCH_TARGET_ADDR,
                       IARG_BOOL, !INS_IsDirectCall(ins),
                       IARG_BOOL, INS_IsRet(ins),
                       IARG_END);
      return true;
    }
  }
  return false;
}

//--------------------------------------------------------------------------
// Insert a call to ins_logic_cb for every instruction which is either
// a call, branch, ret, syscall or invalid (i.e., UD2) and, also, to the
// 1st instruction in the basic block
//lint -e{1746} parameter 'ins' could be made const reference
bool instrumenter_t::add_bbl_logic_cb(INS ins, bool first)
{
  if( tracing_bblock )
  {
    if ( (first || INS_IsBranchOrCall(ins) || INS_IsRet(ins) || INS_IsSyscall(ins) || !ins.is_valid()) )
    {
      pin_tev_type_t tev_type = tev_insn;
      if ( INS_IsCall(ins) )
        tev_type = tev_call;
      else if ( INS_IsRet(ins) )
        tev_type = tev_ret;

      // add the real instruction instrumentation
      INS_InsertIfCall(ins, IPOINT_BEFORE, (AFUNPTR)trc_enabled, IARG_INST_PTR, IARG_END);
      INS_InsertThenCall(ins, IPOINT_BEFORE, (AFUNPTR)ins_logic_cb, IARG_FAST_ANALYSIS_CALL,
              IARG_CONST_CONTEXT, IARG_INST_PTR, IARG_UINT32, (uint32)tev_type, IARG_END);
    }
    return true;
  }
  return false;
}

//--------------------------------------------------------------------------
ADDRINT instrumenter_t::ins_enabled(VOID *)
{
  return tracing_instruction;
}

//--------------------------------------------------------------------------
ADDRINT instrumenter_t::trc_enabled(VOID *)
{
  return tracing_bblock;
}

//--------------------------------------------------------------------------
ADDRINT instrumenter_t::rtn_enabled(VOID *)
{
  return tracing_routine;
}

//--------------------------------------------------------------------------
// This function is called before an instruction is executed
// (used for both instruction and bbl tracing modes)
VOID PIN_FAST_ANALYSIS_CALL instrumenter_t::ins_logic_cb(
  const CONTEXT *ctx,
  VOID *ip,
  pin_tev_type_t tev_type)
{
  if ( check_address((ADDRINT)ip, tev_type) )
    add_to_trace(ctx, (ADDRINT)ip, tev_type);
}

//--------------------------------------------------------------------------
// This function is called for every call/return instruction, here
// ins_ip    - address of instruction itself
// target_ip - address of target instruction our instruction passes control to
VOID PIN_FAST_ANALYSIS_CALL instrumenter_t::rtn_logic_cb(
  ADDRINT ins_ip,
  ADDRINT target_ip,
  BOOL /* is_indirect */,
  BOOL is_ret)
{
  if ( check_address(ins_ip) )
  {
    if ( is_ret )
    {
      if ( log_ret_isns )
        add_to_trace(ins_ip, tev_ret);
    }
    else
    {
      add_to_trace(ins_ip, tev_call);
    }
  }
  if ( !is_ret && check_address(target_ip, tev_insn) )
  {
    // record targets for call instructions. We should do this as they are
    // used by IDA for graph views. The optimal way would be to record only
    // indirect targets (is_indirect == TRUE) and instructions referenced
    // from outside (check_address(ins_ip) == FALSE)
    add_to_trace(target_ip, tev_insn);
  }
}

//--------------------------------------------------------------------------
uint32 instrumenter_t::curr_trace_types()
{
  uint32 types = 0;
  if ( tracing_instruction )
    types |= TF_TRACE_INSN;
  if ( tracing_bblock )
    types |= TF_TRACE_BBLOCK;
  if ( tracing_routine )
    types |= TF_TRACE_ROUTINE;
  return types;
}

//--------------------------------------------------------------------------
inline void instrumenter_t::add_to_trace(
  const CONTEXT *ctx,
  ADDRINT ea,
  pin_tev_type_t tev_type)
{
  DEBUG(3, "add_to_trace1: Adding instruction at %p\n", (void*)ea);

  // set the current thread's context used for reading registers
  thread_data_t *tdata = thread_data_t::get_thread_data(thread_data_t::get_thread_id());
  tdata->save_ctx(ctx);
  store_trace_entry(ctx, ea, tev_type);
}

//--------------------------------------------------------------------------
inline void instrumenter_t::add_to_trace(ADDRINT ea, pin_tev_type_t tev_type)
{
  DEBUG(3, "add_to_trace2: Adding instruction at %p\n", (void*)ea);

  store_trace_entry(NULL, ea, tev_type);
}

//--------------------------------------------------------------------------
inline void instrumenter_t::store_trace_entry(
  const CONTEXT *ctx,
  ADDRINT ea,
  pin_tev_type_t tev_type)
{
  // wait until the tracebuf is read if it's full
  app_wait(&tracebuf_sem);

  if ( tracebuf_is_full() )
    prepare_and_wait_trace_flush();

  trc_element_t trc(PIN_GetTid(), ea, tev_type);
  if ( instrumenter_t::tracing_registers && ctx != NULL )
    get_context_regs(ctx, &trc.regs);

  janitor_for_pinlock_t plj(&tracebuf_lock);
  if ( only_new_instructions )
    register_recorded_insn(ea);
  trace_addrs.push_back(trc);
}

//--------------------------------------------------------------------------
inline size_t instrumenter_t::tracebuf_size()
{
  janitor_for_pinlock_t plj(&tracebuf_lock);
  return trace_addrs.size();
}

//--------------------------------------------------------------------------
inline bool instrumenter_t::tracebuf_is_full()
{
  return tracebuf_size() >= enqueue_limit;
}

//--------------------------------------------------------------------------
// this funcion should be called by an application thread
// when the trace buffer becomes full
inline void instrumenter_t::prepare_and_wait_trace_flush()
{
  {
    janitor_for_pinlock_t process_state_guard(&process_state_lock);
    if ( process_state == APP_STATE_RUNNING )
    {
      DEBUG(2, "prepare_and_wait_trace_flush: generate TRACE_FULL event (trace size=%d)\n", int(trace_addrs.size()));
      pin_debug_event_t event;
      event.eid = TRACE_FULL;
      events.push_front(event);
      process_state = APP_STATE_WAIT_FLUSH;
      sema_clear(&tracebuf_sem);
    }
  }

  // pause the app until the trace is read -
  // client should send "RESUME" request then
  app_wait(&tracebuf_sem);
  DEBUG(2, "flush ended\n");
}

//--------------------------------------------------------------------------
int instrumenter_t::get_trace_events(idatrace_events_t *out_trc_events)
{
  out_trc_events->size = 0;
  janitor_for_pinlock_t plj(&tracebuf_lock);
  do
  {
    if ( trace_addrs.empty() )
      break;

    trc_element_t trc = trace_addrs.front();
    trace_addrs.pop_front();
    out_trc_events->trace[out_trc_events->size].tid = trc.tid;
    out_trc_events->trace[out_trc_events->size].ea = trc.ea;
    out_trc_events->trace[out_trc_events->size].type = trc.type;
    out_trc_events->trace[out_trc_events->size].registers = trc.regs;
  } while ( ++out_trc_events->size < TRACE_EVENTS_SIZE );
  return out_trc_events->size;
}

//--------------------------------------------------------------------------
inline void instrumenter_t::resume()
{
  sema_set(&tracebuf_sem);
}

//--------------------------------------------------------------------------
inline void instrumenter_t::clear_trace()
{
  janitor_for_pinlock_t plj(&tracebuf_lock);
  trace_addrs.clear();
}

//--------------------------------------------------------------------------
inline void instrumenter_t::register_recorded_insn(ADDRINT addr)
{
  all_addrs.push_front(addr);

  // just resize an array when memory limit is reached
  if ( all_addrs.size() >= skip_limit )
    all_addrs.resize(skip_limit);
}

//--------------------------------------------------------------------------
inline bool instrumenter_t::insn_is_registered(ADDRINT addr)
{
  return std::find(all_addrs.begin(), all_addrs.end(), addr) != all_addrs.end();
}

//--------------------------------------------------------------------------
inline bool instrumenter_t::check_address(ADDRINT addr)
{
  if ( break_at_next_inst )
    return true;

  return (trace_everything || (addr >= min_address && addr <= max_address));
}

//--------------------------------------------------------------------------
inline bool instrumenter_t::check_address(ADDRINT addr, pin_tev_type_t type)
{
  if ( !check_address(addr) )
    return false;
  return type != tev_insn || !only_new_instructions || !insn_is_registered(addr);
}

//--------------------------------------------------------------------------
bool instrumenter_t::set_limits(
  bool only_new,
  uint32 enq_size,
  const char *imgname)
{
  only_new_instructions = only_new;
  enqueue_limit = enq_size;
  MSG("Setting maximum enqueue limit to %d, "
      "tracing image '%s', new instructions only %d\n",
       enqueue_limit, imgname, only_new_instructions);
  if ( image_name.empty() || image_name != imgname )
  {
    image_name = imgname;
    trace_everything = image_name == "*";
    if ( trace_everything )
      MSG("Image name set to '*', tracing everything!\n");
  }
  MSG("Correct configuration received\n");
  return true;
}

//--------------------------------------------------------------------------
const char *pin_basename(const char *path)
{
  if ( path != NULL )
  {
    const char *f1 = strrchr(path, '/');
    const char *f2 = strrchr(path, '\\');
    const char *file = max(f1, f2);
    if ( file != NULL )
      return file+1;
  }
  return path;
}

//--------------------------------------------------------------------------
void instrumenter_t::process_image(const IMG &img, bool as_default)
{
  // by default, we set the limits of the trace to the main binary
  ADDRINT start_ea = IMG_LowAddress(img);
  ADDRINT end_ea = IMG_HighAddress(img);

  if ( min_address != start_ea || max_address != end_ea )
  {
    string base_head  = pin_basename(IMG_Name(img).c_str());
    string base_image = pin_basename(image_name.c_str());
    transform(base_head.begin(), base_head.end(), base_head.begin(), ::tolower);
    transform(base_image.begin(), base_image.end(), base_image.begin(), ::tolower);

    if ( (as_default && image_name.empty()) || base_head == base_image )
    {
      MSG("Image boundaries: Min EA %p Max EA %p", (void*)start_ea, (void*)end_ea);
      min_address = start_ea;
      max_address = end_ea;
    }
  }
}

//--------------------------------------------------------------------------
inline bool instrumenter_t::instr_state_ok()
{
  return state == INSTR_STATE_OK;
}

#if 0
//--------------------------------------------------------------------------
static void dump_sizes(void)
{
  MSG("Sizeof pin_module_info_t %d\n", sizeof(pin_module_info_t));
  MSG("Sizeof pin_e_breakpoint_t %d\n", sizeof(pin_e_breakpoint_t));
  MSG("Sizeof pin_e_exception_t %d\n", sizeof(pin_e_exception_t));
  MSG("Sizeof pin_debug_event_t %d\n", sizeof(pin_debug_event_t));
  MSG("Sizeof idapin_packet_t %d\n", sizeof(idapin_packet_t));
  MSG("Sizeof memimages_pkt_t %d\n", sizeof(memimages_pkt_t));
  MSG("Sizeof pin_memory_info_t %d\n", sizeof(pin_memory_info_t));
  MSG("Sizeof idamem_packet_t %d\n", sizeof(idamem_packet_t));
  MSG("Sizeof idamem_response_pkt_t %d\n", sizeof(idamem_response_pkt_t));
  MSG("Sizeof idapin_registers_t %d\n", sizeof(idapin_registers_t));
  MSG("Sizeof idatrace_data_t %d\n", sizeof(idatrace_data_t));
  MSG("Sizeof idatrace_events_t %d\n", sizeof(idatrace_events_t));
  MSG("Sizeof idabpt_packet_t %d\n", sizeof(idabpt_packet_t);
  MSG("Sizeof idalimits_packet_t %d\n", sizeof(idalimits_packet_t));
}
#endif

