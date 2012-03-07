#ifndef _X509DEC_H_
#define _X509DEC_H_

#include <sys/queue.h>

TAILQ_HEAD(tailq, name);

#if defined(__linux__)

#ifndef TAILQ_HEAD_INITIALIZER
#define	TAILQ_HEAD_INITIALIZER(head)					\
	{ NULL, &(head).tqh_first }
#endif /* TAILQ_FIRST */

#ifndef TAILQ_FIRST
#define	TAILQ_FIRST(head)	((head)->tqh_first)
#endif /* TAILQ_FIRST */

#ifndef TAILQ_NEXT
#define	TAILQ_NEXT(elm, field) ((elm)->field.tqe_next)
#endif /* TAILQ_NEXT */

#ifndef TAILQ_FOREACH
#define	TAILQ_FOREACH(var, head, field)					\
	for ((var) = TAILQ_FIRST((head));				\
	    (var);							\
	    (var) = TAILQ_NEXT((var), field))
#endif /* TAILQ_FOREACH */

size_t strlcpy(char *dst, const char *src, size_t size) {
	char       *dstptr = dst;
	size_t     tocopy  = size;
	const char *srcptr = src;

	if (tocopy && --tocopy) {
		do {
			if (!(*dstptr++ = *srcptr++)) break;
		} while (--tocopy);
	}
	if (!tocopy) {
		if (size) *dstptr = 0;
		while (*srcptr++);
	}

	return (srcptr - src - 1);
}

#endif

struct name {
	int name_type;
	int name_len;
	unsigned char *name_buf;
	TAILQ_ENTRY(name) names;
};
#endif	/*  _X509DEC_H_*/
