/* ------------------------------------------------------------------------*/
/*                                                                         */
/*   OBJECTS.H                                                             */
/*                                                                         */
/*   Copyright (c) Borland International 1991                              */
/*   All Rights Reserved.                                                  */
/*                                                                         */
/*   defines the classes TPoint, TRect, TCollection, and TSortedCollection */
/*                                                                         */
/* ------------------------------------------------------------------------*/

#if defined( Uses_TPoint ) && !defined( __TPoint )
#define __TPoint

class TPoint
{

public:

    TPoint& operator+=( const TPoint& adder );
    TPoint& operator-=( const TPoint& subber );
    friend TPoint operator - ( const TPoint& one, const TPoint& two);
    friend TPoint operator + ( const TPoint& one, const TPoint& two);
    friend int operator == ( const TPoint& one, const TPoint& two);
    friend int operator != ( const TPoint& one, const TPoint& two);

    int x,y;

};

inline TPoint& TPoint::operator += ( const TPoint& adder )
{
    x += adder.x;
    y += adder.y;
    return *this;
}

inline TPoint& TPoint::operator -= ( const TPoint& subber )
{
    x -= subber.x;
    y -= subber.y;
    return *this;
}

#ifndef NO_TV_STREAMS
inline ipstream& operator >> ( ipstream& is, TPoint& p )
    { return is >> p.x >> p.y; }
inline ipstream& operator >> ( ipstream& is, TPoint*& p )
    { return is >> p->x >> p->y; }

inline opstream& operator << ( opstream& os, TPoint& p )
    { return os << p.x << p.y; }
inline opstream& operator << ( opstream& os, TPoint* p )
    { return os << p->x << p->y; }
#endif  // !NO_TV_STREAMS

#endif  // Uses_TPoint

#if defined( Uses_TRect ) && !defined( __TRect )
#define __TRect

class TRect
{

public:

    TRect( int ax, int ay, int bx, int by );
    TRect( TPoint p1, TPoint p2 );
    TRect();

    void move( int aDX, int aDY );
    void grow( int aDX, int aDY );
    void intersect( const TRect& r );
    void Union( const TRect& r );
    Boolean contains( const TPoint& p ) const;
    Boolean operator == ( const TRect& r ) const;
    Boolean operator != ( const TRect& r ) const;
    Boolean isEmpty();

    TPoint a, b;

};

inline TRect::TRect( int ax, int ay, int bx, int by)
{
    a.x = ax;
    a.y = ay;
    b.x = bx;
    b.y = by;
}

inline TRect::TRect( TPoint p1, TPoint p2 )
{
    a = p1;
    b = p2;
}

inline TRect::TRect()
{
}

inline void TRect::move( int aDX, int aDY )
{
    a.x += aDX;
    a.y += aDY;
    b.x += aDX;
    b.y += aDY;
}

inline void TRect::grow( int aDX, int aDY )
{
    a.x -= aDX;
    a.y -= aDY;
    b.x += aDX;
    b.y += aDY;
}

inline void TRect::intersect( const TRect& r )
{
    a.x = qmax( a.x, r.a.x );
    a.y = qmax( a.y, r.a.y );
    b.x = qmin( b.x, r.b.x );
    b.y = qmin( b.y, r.b.y );
}

inline void TRect::Union( const TRect& r )
{
    a.x = qmin( a.x, r.a.x );
    a.y = qmin( a.y, r.a.y );
    b.x = qmax( b.x, r.b.x );
    b.y = qmax( b.y, r.b.y );
}

inline Boolean TRect::contains( const TPoint& p ) const
{
    return Boolean(
        p.x >= a.x && p.x < b.x && p.y >= a.y && p.y < b.y
        );
}

inline Boolean TRect::operator == ( const TRect& r) const
{
    return Boolean( a == r.a && b == r.b );
}

inline Boolean TRect::operator != ( const TRect& r ) const
{
    return Boolean( !(*this == r) );
}

inline Boolean TRect::isEmpty()
{
    return Boolean( a.x >= b.x || a.y >= b.y );
}

#ifndef NO_TV_STREAMS
inline ipstream& operator >> ( ipstream& is, TRect& r )
    { return is >> r.a >> r.b; }
inline ipstream& operator >> ( ipstream& is, TRect*& r )
    { return is >> r->a >> r->b; }

inline opstream& operator << ( opstream& os, TRect& r )
    { return os << r.a << r.b; }
inline opstream& operator << ( opstream& os, TRect* r )
    { return os << r->a << r->b; }
#endif  // ifndef NO_TV_STREAMS

#endif  // Uses_TRect

#if defined( Uses_TCollection ) && !defined( __TCollection )
#define __TCollection

class TCollection : public virtual TNSCollection
#ifndef NO_TV_STREAMS
                                                , public TStreamable
#endif  // ifndef NO_TV_STREAMS
{

public:

    TCollection( ccIndex aLimit, ccIndex aDelta )
        { delta = aDelta; setLimit( aLimit ); }

private:

#ifndef NO_TV_STREAMS
    virtual const char *streamableName() const
        { return name; }

    virtual void *readItem( ipstream& ) = 0;
    virtual void writeItem( void *, opstream& ) = 0;


protected:

    TCollection( StreamableInit );
    virtual void *read( ipstream& );
    virtual void write( opstream& );

public:

    static const char * const name;
#endif  // ifndef NO_TV_STREAMS

};

#ifndef NO_TV_STREAMS
inline ipstream& operator >> ( ipstream& is, TCollection& cl )
    { return is >> (TStreamable&)cl; }
inline ipstream& operator >> ( ipstream& is, TCollection*& cl )
    { return is >> (void *&)cl; }

inline opstream& operator << ( opstream& os, TCollection& cl )
    { return os << (TStreamable&)cl; }
inline opstream& operator << ( opstream& os, TCollection* cl )
    { return os << (TStreamable *)cl; }
#endif  // ifndef NO_TV_STREAMS

#endif  // Uses_TCollection

#if defined( Uses_TSortedCollection ) && !defined( __TSortedCollection )
#define __TSortedCollection

class TSortedCollection : public TNSSortedCollection, public TCollection
{

public:

    TSortedCollection( ccIndex aLimit, ccIndex aDelta) :
        TCollection( aLimit, aDelta ) {}

private:

    virtual int compare( void *key1, void *key2 ) = 0;

#ifndef NO_TV_STREAMS
    virtual const char *streamableName() const
        { return name; }
    virtual void *readItem( ipstream& ) = 0;
    virtual void writeItem( void *, opstream& ) = 0;

protected:

    TSortedCollection( StreamableInit );
    virtual void *read( ipstream& );
    virtual void write( opstream& );

public:

    static const char * const name;
#endif  // ifndef NO_TV_STREAMS

};

#ifndef NO_TV_STREAMS
inline ipstream& operator >> ( ipstream& is, TSortedCollection& cl )
    { return is >> (TStreamable&)cl; }
inline ipstream& operator >> ( ipstream& is, TSortedCollection*& cl )
    { return is >> (void *&)cl; }

inline opstream& operator << ( opstream& os, TSortedCollection& cl )
    { return os << (TStreamable&)cl; }
inline opstream& operator << ( opstream& os, TSortedCollection* cl )
    { return os << (TStreamable *)cl; }
#endif  // ifndef NO_TV_STREAMS

#endif  // Uses_TSortedCollection


