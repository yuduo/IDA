/*

    IDA trace: PIN tool to communicate with IDA's debugger

*/
#ifndef _IDADBG_H
#define _IDADBG_H

#include <vector>

using namespace std;

typedef unsigned int uint32;
typedef unsigned char uchar;

#define PIN_PROTOCOL_VERSION 2

#ifdef IDA_SDK_VERSION
// IDA specific declarations
#   define pin_strncpy  ::qstrncpy
#   define pin_snprintf ::qsnprintf
#   define addr_t         ea_t
#   define pin_thid       thid_t
#   define pin_size_t     uint32
#   define pin_pid_t      pid_t
#   define pin_event_id_t event_id_t
#   define pin_bpttype_t  bpttype_t
#ifdef __EA64__
#   define BITNESS 2
#   define PIN_64
#else
#   define BITNESS 1
#endif
#ifdef __X64__
#   define PIN_64
#endif
#else
// PIN specific declarations
#   define pin_strncpy  strncpy
#   define pin_snprintf snprintf
#   define addr_t ADDRINT
#   define ea_t addr_t
#   define pin_thid OS_THREAD_ID
#   define NO_THREAD pin_thid(0)
#   define pin_size_t uint32
#   define pin_pid_t  uint32
#   define MAXSTR 1024
#   define BADADDR -1

#if defined(_MSC_VER)
typedef unsigned __int64 uint64;
typedef          __int64 int64;
#else
typedef unsigned long long uint64;
typedef          long long int64;
#endif

#ifdef TARGET_IA32
#   define BITNESS    1
#   define HEX_FMT    "%x"
#   define HEX64_FMT  "%llx"
#   define HEX64T_FMT "%llux"
#else
#   define BITNESS   2
#   define PIN_64    1
#   define HEX_FMT   "%lx"
#   define HEX64_FMT "%llx"
#   define HEX64T_FMT "%llux"
#endif

// structures and definitions copied from IDA SDK (idd.hpp)

#define SEGPERM_EXEC  1 // Execute
#define SEGPERM_WRITE 2 // Write
#define SEGPERM_READ  4 // Read

// the replica of event_id_t declared in idd.hpp
enum pin_event_id_t
{
  NO_EVENT       = 0x00000000, // Not an interesting event. This event can be
                               // used if the debugger module needs to return
                               // an event but there are no valid events.
  PROCESS_START  = 0x00000001, // New process has been started.
  PROCESS_EXIT   = 0x00000002, // Process has been stopped.
  THREAD_START   = 0x00000004, // New thread has been started.
  THREAD_EXIT    = 0x00000008, // Thread has been stopped.
  BREAKPOINT     = 0x00000010, // Breakpoint has been reached. IDA will complain
                               // about unknown breakpoints, they should be reported
                               // as exceptions.
  STEP           = 0x00000020, // One instruction has been executed. Spurious
                               // events of this kind are silently ignored by IDA.
  EXCEPTION      = 0x00000040, // Exception.
  LIBRARY_LOAD   = 0x00000080, // New library has been loaded.
  LIBRARY_UNLOAD = 0x00000100, // Library has been unloaded.
  INFORMATION    = 0x00000200, // User-defined information.
                               // This event can be used to return empty information
                               // This will cause IDA to call get_debug_event()
                               // immediately once more.
  _SYSCALL       = 0x00000400, // Syscall (not used yet).
  WINMESSAGE     = 0x00000800, // Window message (not used yet).
  PROCESS_ATTACH = 0x00001000, // Successfully attached to running process.
  PROCESS_DETACH = 0x00002000, // Successfully detached from process.
  PROCESS_SUSPEND= 0x00004000, // Process has been suspended..
                               // This event can be used by the debugger module
                               // to signal if the process spontaneously gets
                               // suspended (not because of an exception,
                               // breakpoint, or single step). IDA will silently
                               // switch to the 'suspended process' mode without
                               // displaying any messages.
  TRACE_FULL     = 0x00008000, // The trace being recorded is full.
};

// Trace event types:
enum pin_tev_type_t
{
  tev_none = 0, // no event
  tev_insn,     // an instruction trace
  tev_call,     // a function call trace
  tev_ret,      // a function return trace
  tev_bpt,      // write, read/write, execution trace
  tev_mem,      // memory layout changed
  tev_event,    // debug event occurred
  tev_trace,    // a trace event (used for tracers like PIN)
  tev_max,      // first unused event type
};

// Hardware breakpoint types. Fire the breakpoint upon:
typedef int bpttype_t;
const bpttype_t
  BPT_OLD_EXEC = 0,             // (obsolute: execute instruction)
  BPT_WRITE    = 1,             // Write access
  BPT_READ     = 2,             // Read access
  BPT_RDWR     = 3,             // Read/write access
  BPT_SOFT     = 4,             // Software breakpoint
  BPT_EXEC     = 8;             // Execute instruction

#endif

//--------------------------------------------------------------------------
// OS id - will send by PIN tool in response to PTT_HELLO
enum pin_target_os_t
{
  PIN_TARGET_OS_UNDEF   = 0x0000,
  PIN_TARGET_OS_WINDOWS = 0x1000,
  PIN_TARGET_OS_LINUX   = 0x2000,
  PIN_TARGET_OS_MAC     = 0x4000,
};

//--------------------------------------------------------------------------
#pragma pack(push, 1)

struct pin_module_info_t
{
  char name[MAXSTR];    // full name of the module.
  uint64 base;          // module base address. if unknown pass BADADDR
  pin_size_t size;      // module size. if unknown pass 0
  uint64 rebase_to;     // if not BADADDR, then rebase the program to the specified address
};

struct pin_e_breakpoint_t
{
  uint64 hea;           // Possible address referenced by hardware breakpoints
  uint64 kea;           // Address of the triggered bpt from the kernel's point
                        // of view (for some systems with special memory mappings,
                        // the triggered ea might be different from event ea).
                        // Use to BADADDR for flat memory model.
};

struct pin_e_exception_t
{
  uint32 code;          // Exception code
  bool can_cont;        // Execution of the process can continue after this exception?
  uint64 ea;            // Possible address referenced by the exception
  char info[MAXSTR];    // Exception message
};

//--------------------------------------------------------------------------
struct pin_debug_event_t
{
  pin_debug_event_t(uint32 evid = NO_EVENT): eid(evid), ea(BADADDR) {}
                          // The following fields must be filled for all events:
  uint32    eid;          // Event code (used to decipher 'info' union)
  pin_pid_t pid;          // Process where the event occured
  pin_thid tid;           // Thread where the event occured
  uint64 ea;              // Address where the event occured
  bool handled;           // Is event handled by the debugger?
                          // (from the system's point of view)
                          // Meaningful for EXCEPTION events
  union
  {
    pin_module_info_t modinfo; // PROCESS_START, PROCESS_ATTACH, LIBRARY_LOAD
    int exit_code;             // PROCESS_EXIT, THREAD_EXIT
    char info[MAXSTR];         // LIBRARY_UNLOAD (unloaded library name)
                               // INFORMATION (will be displayed in the
                               //              messages window if not empty)
    pin_e_breakpoint_t bpt;    // BREAKPOINT
    pin_e_exception_t exc;     // EXCEPTION
  };
};

//--------------------------------------------------------------------------
enum packet_type_t
{
  PTT_ACK = 0,
  PTT_ERROR = 1,
  PTT_HELLO = 2,
  PTT_EXIT_PROCESS = 3,
  PTT_START_PROCESS = 4,
  PTT_DEBUG_EVENT = 5,
  PTT_READ_EVENT = 6,
  PTT_MEMORY_INFO = 7,
  PTT_READ_MEMORY = 8,
  PTT_DETACH = 9,
  PTT_COUNT_TRACE = 10,
  PTT_READ_TRACE = 11,
  PTT_CLEAR_TRACE = 12,
  PTT_PAUSE = 13,
  PTT_RESUME = 14,
  PTT_RESUME_START = 15,    // not used since v.2
  PTT_ADD_BPT = 16,
  PTT_DEL_BPT = 17,
  PTT_RESUME_BPT = 18,      // not used since v.2
  PTT_CAN_READ_REGS = 19,
  PTT_READ_REGS = 20,
  PTT_SET_TRACE = 21,
  PTT_SET_OPTIONS = 22,
  PTT_STEP = 23,
  PTT_THREAD_SUSPEND = 24,
  PTT_THREAD_RESUME = 25,
  PTT_END = 26
};

//--------------------------------------------------------------------------
struct idapin_packet_t
{
  packet_type_t code;
  pin_size_t size;
  uint64 data;

  idapin_packet_t() : code(PTT_ACK), size(0), data(BADADDR)
  {
  }
};

//--------------------------------------------------------------------------
struct idapin_packet_v1_t
{
  packet_type_t code;
  pin_size_t size;
  addr_t data;

  idapin_packet_v1_t() : code(PTT_ACK), size(0), data(BADADDR)
  {
  }
};

//--------------------------------------------------------------------------
struct memimages_pkt_t
{
  packet_type_t code;
  pin_size_t size;

  memimages_pkt_t(packet_type_t _code, pin_size_t _size) : code(_code), size(_size)
  {
  }

  memimages_pkt_t() : code(PTT_ACK), size(0)
  {
  }
};

//--------------------------------------------------------------------------
struct pin_memory_info_t
{
  uint64   startEA;
  uint64   endEA;
  pin_size_t name_size;        // Size of the memory area name
  char   name[MAXSTR];         // Memory area name
  uchar  bitness;              // Number of bits in segment addresses (0-16bit, 1-32bit, 2-64bit)
  uchar  perm;                 // Memory area permissions (0-no information): see segment.hpp
};
typedef vector<pin_memory_info_t> pin_meminfo_vec_t;

//--------------------------------------------------------------------------

enum mem_actions_t
{
  MA_READ=0,
  MA_WRITE
};

struct idamem_packet_t
{
  mem_actions_t action;               // 0-Read, 1-Write
  uint64 address;
  pin_size_t size;
};

#define MEM_CHUNK_SIZE 1024
struct idamem_response_pkt_t
{
  packet_type_t code;
  pin_size_t size;
  unsigned char buf[MEM_CHUNK_SIZE];
};

#define TRACE_EVENTS_SIZE 1000

struct idapin_registers_t
{
  uint64 eax;
  uint64 ebx;
  uint64 ecx;
  uint64 edx;
  uint64 esi;
  uint64 edi;
  uint64 ebp;
  uint64 esp;
  uint64 eip;
  uint64 r8;
  uint64 r9;
  uint64 r10;
  uint64 r11;
  uint64 r12;
  uint64 r13;
  uint64 r14;
  uint64 r15;
  uint64 eflags;
  uint64 cs;
  uint64 ds;
  uint64 es;
  uint64 fs;
  uint64 gs;
  uint64 ss;
};

struct idatrace_data_t
{
  uint64   ea;
  pin_thid tid;
  uint32   type;
  idapin_registers_t registers;
};

struct idatrace_events_t
{
  packet_type_t code;
  pin_size_t size;
  idatrace_data_t trace[TRACE_EVENTS_SIZE];
};

struct idabpt_packet_t
{
  bpttype_t type;
  uint64 ea;
  pin_size_t size;
};

enum trace_flags_t
{
  TF_TRACE_STEP       = 0x0001,
  TF_TRACE_INSN       = 0x0002,
  TF_TRACE_BBLOCK     = 0x0004,
  TF_TRACE_ROUTINE    = 0x0008,
  TF_REGISTERS        = 0x0010,
  TF_LOG_RET          = 0x0020,
  TF_TRACE_EVERYTHING = 0x0040,
  TF_ONLY_NEW_ISNS    = 0x0080,
  TF_LOGGING          = 0x0100,
};

struct idalimits_packet_t
{
  // name (and possibly path) of the image to trace, '\0' if we want to
  // trace everything (library calls, etc...)
  char image_name[MAXSTR];
  // maximum number of tevs to enqueue
  uint32 trace_limit;
  // bytes of memory to save if enabled
  pin_size_t bytes;
  // only record new instructions?
  bool only_new;
};

#pragma pack(pop)

#endif
