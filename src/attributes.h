#ifndef DW_ATTRIBUTES_H
#define DW_ATTRIBUTES_H

#ifndef __has_builtin
#  define __has_builtin(x) 0
#endif

#ifndef __has_attribute
#  define __has_attribute(x) 0
#endif

#if !defined(__glibc_objsize)
#  define __glibc_objsize(p) __builtin_object_size((p), 0)
#endif

#if __has_attribute(__always_inline__) || defined(__GNUC__)
#  define DW_ALWAYS_INLINE __attribute__((__always_inline__))
#else
#  define DW_ALWAYS_INLINE
#endif

#if __has_attribute(__noinline__) || defined(__GNUC__)
#  define DW_NOINLINE __attribute__((__noinline__))
#else
#  define DW_NOINLINE
#endif

#if __has_attribute(__used__) || defined(__GNUC__)
#  define DW_USED __attribute__((__used__))
#else
#  define DW_USED
#endif

#if __has_attribute(__aligned__) || defined(__GNUC__)
#  define DW_ALIGNED(x) __attribute__((__aligned__(x)))
#else
#  define DW_ALIGNED(x)
#endif

#if __has_attribute(__pure__) || defined(__GNUC__)
#  define DW_PURE __attribute__((__pure__))
#else
#  define DW_PURE
#endif

#if __has_attribute(__constructor__) || defined(__GNUC__)
#  define DW_CONSTRUCTOR(priority) __attribute__((__constructor__(priority)))
#else
#  define DW_CONSTRUCTOR(priority)
#endif

#if __has_builtin(__builtin_expect)
#  define likely(x)   __builtin_expect(!!(x), 1)
#  define unlikely(x) __builtin_expect(!!(x), 0)
#else
#  define likely(x)   (x)
#  define unlikely(x) (x)
#endif

#if __has_attribute(__visibility__) || defined(__GNUC__)
#  define DW_INTERNAL __attribute__((__visibility__("hidden")))
#else
#  define DW_INTERNAL
#endif

#endif /* DW_ATTRIBUTES_H */
