/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */

/* THIS FILE IS AUTOGENERATED BY BPFTOOL! */
#ifndef __READAHEAD_BPF_SKEL_H__
#define __READAHEAD_BPF_SKEL_H__

#include <errno.h>
#include <stdlib.h>
#include <bpf/libbpf.h>

struct readahead_bpf {
	struct bpf_object_skeleton *skeleton;
	struct bpf_object *obj;
	struct {
		struct bpf_map *in_readahead;
		struct bpf_map *birth;
		struct bpf_map *bss;
	} maps;
	struct {
		struct bpf_program *do_page_cache_ra;
		struct bpf_program *page_cache_alloc_ret;
		struct bpf_program *do_page_cache_ra_ret;
		struct bpf_program *mark_page_accessed;
	} progs;
	struct {
		struct bpf_link *do_page_cache_ra;
		struct bpf_link *page_cache_alloc_ret;
		struct bpf_link *do_page_cache_ra_ret;
		struct bpf_link *mark_page_accessed;
	} links;
	struct readahead_bpf__bss {
		struct hist hist;
	} *bss;

#ifdef __cplusplus
	static inline struct readahead_bpf *open(const struct bpf_object_open_opts *opts = nullptr);
	static inline struct readahead_bpf *open_and_load();
	static inline int load(struct readahead_bpf *skel);
	static inline int attach(struct readahead_bpf *skel);
	static inline void detach(struct readahead_bpf *skel);
	static inline void destroy(struct readahead_bpf *skel);
	static inline const void *elf_bytes(size_t *sz);
#endif /* __cplusplus */
};

static void
readahead_bpf__destroy(struct readahead_bpf *obj)
{
	if (!obj)
		return;
	if (obj->skeleton)
		bpf_object__destroy_skeleton(obj->skeleton);
	free(obj);
}

static inline int
readahead_bpf__create_skeleton(struct readahead_bpf *obj);

static inline struct readahead_bpf *
readahead_bpf__open_opts(const struct bpf_object_open_opts *opts)
{
	struct readahead_bpf *obj;
	int err;

	obj = (struct readahead_bpf *)calloc(1, sizeof(*obj));
	if (!obj) {
		errno = ENOMEM;
		return NULL;
	}

	err = readahead_bpf__create_skeleton(obj);
	if (err)
		goto err_out;

	err = bpf_object__open_skeleton(obj->skeleton, opts);
	if (err)
		goto err_out;

	return obj;
err_out:
	readahead_bpf__destroy(obj);
	errno = -err;
	return NULL;
}

static inline struct readahead_bpf *
readahead_bpf__open(void)
{
	return readahead_bpf__open_opts(NULL);
}

static inline int
readahead_bpf__load(struct readahead_bpf *obj)
{
	return bpf_object__load_skeleton(obj->skeleton);
}

static inline struct readahead_bpf *
readahead_bpf__open_and_load(void)
{
	struct readahead_bpf *obj;
	int err;

	obj = readahead_bpf__open();
	if (!obj)
		return NULL;
	err = readahead_bpf__load(obj);
	if (err) {
		readahead_bpf__destroy(obj);
		errno = -err;
		return NULL;
	}
	return obj;
}

static inline int
readahead_bpf__attach(struct readahead_bpf *obj)
{
	return bpf_object__attach_skeleton(obj->skeleton);
}

static inline void
readahead_bpf__detach(struct readahead_bpf *obj)
{
	bpf_object__detach_skeleton(obj->skeleton);
}

static inline const void *readahead_bpf__elf_bytes(size_t *sz);

static inline int
readahead_bpf__create_skeleton(struct readahead_bpf *obj)
{
	struct bpf_object_skeleton *s;
	int err;

	s = (struct bpf_object_skeleton *)calloc(1, sizeof(*s));
	if (!s)	{
		err = -ENOMEM;
		goto err;
	}

	s->sz = sizeof(*s);
	s->name = "readahead_bpf";
	s->obj = &obj->obj;

	/* maps */
	s->map_cnt = 3;
	s->map_skel_sz = sizeof(*s->maps);
	s->maps = (struct bpf_map_skeleton *)calloc(s->map_cnt, s->map_skel_sz);
	if (!s->maps) {
		err = -ENOMEM;
		goto err;
	}

	s->maps[0].name = "in_readahead";
	s->maps[0].map = &obj->maps.in_readahead;

	s->maps[1].name = "birth";
	s->maps[1].map = &obj->maps.birth;

	s->maps[2].name = "readahea.bss";
	s->maps[2].map = &obj->maps.bss;
	s->maps[2].mmaped = (void **)&obj->bss;

	/* programs */
	s->prog_cnt = 4;
	s->prog_skel_sz = sizeof(*s->progs);
	s->progs = (struct bpf_prog_skeleton *)calloc(s->prog_cnt, s->prog_skel_sz);
	if (!s->progs) {
		err = -ENOMEM;
		goto err;
	}

	s->progs[0].name = "do_page_cache_ra";
	s->progs[0].prog = &obj->progs.do_page_cache_ra;
	s->progs[0].link = &obj->links.do_page_cache_ra;

	s->progs[1].name = "page_cache_alloc_ret";
	s->progs[1].prog = &obj->progs.page_cache_alloc_ret;
	s->progs[1].link = &obj->links.page_cache_alloc_ret;

	s->progs[2].name = "do_page_cache_ra_ret";
	s->progs[2].prog = &obj->progs.do_page_cache_ra_ret;
	s->progs[2].link = &obj->links.do_page_cache_ra_ret;

	s->progs[3].name = "mark_page_accessed";
	s->progs[3].prog = &obj->progs.mark_page_accessed;
	s->progs[3].link = &obj->links.mark_page_accessed;

	s->data = readahead_bpf__elf_bytes(&s->data_sz);

	obj->skeleton = s;
	return 0;
err:
	bpf_object__destroy_skeleton(s);
	return err;
}

static inline const void *readahead_bpf__elf_bytes(size_t *sz)
{
	static const char data[] __attribute__((__aligned__(8))) = "\
\x7f\x45\x4c\x46\x02\x01\x01\0\0\0\0\0\0\0\0\0\x01\0\xf7\0\x01\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\x20\x1f\0\0\0\0\0\0\0\0\0\0\x40\0\0\0\0\0\x40\0\x10\0\
\x01\0\0\x2e\x73\x74\x72\x74\x61\x62\0\x2e\x73\x79\x6d\x74\x61\x62\0\x66\x65\
\x6e\x74\x72\x79\x2f\x64\x6f\x5f\x70\x61\x67\x65\x5f\x63\x61\x63\x68\x65\x5f\
\x72\x61\0\x66\x65\x78\x69\x74\x2f\x5f\x5f\x70\x61\x67\x65\x5f\x63\x61\x63\x68\
\x65\x5f\x61\x6c\x6c\x6f\x63\0\x66\x65\x78\x69\x74\x2f\x64\x6f\x5f\x70\x61\x67\
\x65\x5f\x63\x61\x63\x68\x65\x5f\x72\x61\0\x66\x65\x6e\x74\x72\x79\x2f\x6d\x61\
\x72\x6b\x5f\x70\x61\x67\x65\x5f\x61\x63\x63\x65\x73\x73\x65\x64\0\x2e\x62\x73\
\x73\0\x6c\x69\x63\x65\x6e\x73\x65\0\x2e\x6d\x61\x70\x73\0\x72\x65\x61\x64\x61\
\x68\x65\x61\x64\x2e\x62\x70\x66\x2e\x63\0\x4c\x42\x42\x31\x5f\x32\0\x4c\x42\
\x42\x33\x5f\x32\x33\0\x4c\x42\x42\x33\x5f\x32\x32\0\x4c\x42\x42\x33\x5f\x31\
\x30\0\x4c\x42\x42\x33\x5f\x35\0\x4c\x42\x42\x33\x5f\x37\0\x4c\x42\x42\x33\x5f\
\x39\0\x4c\x42\x42\x33\x5f\x31\x39\0\x4c\x42\x42\x33\x5f\x31\x32\0\x4c\x42\x42\
\x33\x5f\x31\x34\0\x4c\x42\x42\x33\x5f\x31\x36\0\x4c\x42\x42\x33\x5f\x31\x38\0\
\x4c\x42\x42\x33\x5f\x32\x31\0\x64\x6f\x5f\x70\x61\x67\x65\x5f\x63\x61\x63\x68\
\x65\x5f\x72\x61\0\x69\x6e\x5f\x72\x65\x61\x64\x61\x68\x65\x61\x64\0\x70\x61\
\x67\x65\x5f\x63\x61\x63\x68\x65\x5f\x61\x6c\x6c\x6f\x63\x5f\x72\x65\x74\0\x62\
\x69\x72\x74\x68\0\x68\x69\x73\x74\0\x64\x6f\x5f\x70\x61\x67\x65\x5f\x63\x61\
\x63\x68\x65\x5f\x72\x61\x5f\x72\x65\x74\0\x6d\x61\x72\x6b\x5f\x70\x61\x67\x65\
\x5f\x61\x63\x63\x65\x73\x73\x65\x64\0\x4c\x49\x43\x45\x4e\x53\x45\0\x2e\x72\
\x65\x6c\x66\x65\x6e\x74\x72\x79\x2f\x64\x6f\x5f\x70\x61\x67\x65\x5f\x63\x61\
\x63\x68\x65\x5f\x72\x61\0\x2e\x72\x65\x6c\x66\x65\x78\x69\x74\x2f\x5f\x5f\x70\
\x61\x67\x65\x5f\x63\x61\x63\x68\x65\x5f\x61\x6c\x6c\x6f\x63\0\x2e\x72\x65\x6c\
\x66\x65\x78\x69\x74\x2f\x64\x6f\x5f\x70\x61\x67\x65\x5f\x63\x61\x63\x68\x65\
\x5f\x72\x61\0\x2e\x72\x65\x6c\x66\x65\x6e\x74\x72\x79\x2f\x6d\x61\x72\x6b\x5f\
\x70\x61\x67\x65\x5f\x61\x63\x63\x65\x73\x73\x65\x64\0\x2e\x42\x54\x46\0\x2e\
\x42\x54\x46\x2e\x65\x78\x74\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\x86\0\0\0\x04\0\xf1\xff\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x03\0\x03\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x03\0\x04\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\0\0\x96\0\0\0\0\0\x04\0\xd0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x03\0\x05\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x03\0\x06\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\0\0\0\x9d\0\0\0\0\0\x06\0\xb0\x02\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xa5\0\0\0\0\0\
\x06\0\x68\x02\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xad\0\0\0\0\0\x06\0\x38\x01\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\xb5\0\0\0\0\0\x06\0\xb0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xbc\
\0\0\0\0\0\x06\0\xd8\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xc3\0\0\0\0\0\x06\0\0\x01\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\xca\0\0\0\0\0\x06\0\x10\x02\0\0\0\0\0\0\0\0\0\0\0\0\
\0\0\xd2\0\0\0\0\0\x06\0\x68\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xda\0\0\0\0\0\x06\
\0\x90\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xe2\0\0\0\0\0\x06\0\xc0\x01\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\xea\0\0\0\0\0\x06\0\xe8\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xf2\0\
\0\0\0\0\x06\0\x38\x02\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xfa\0\0\0\x12\0\x03\0\0\0\0\
\0\0\0\0\0\x70\0\0\0\0\0\0\0\x0b\x01\0\0\x11\0\x09\0\0\0\0\0\0\0\0\0\x20\0\0\0\
\0\0\0\0\x18\x01\0\0\x12\0\x04\0\0\0\0\0\0\0\0\0\xe0\0\0\0\0\0\0\0\x2d\x01\0\0\
\x11\0\x09\0\x20\0\0\0\0\0\0\0\x20\0\0\0\0\0\0\0\x33\x01\0\0\x11\0\x07\0\0\0\0\
\0\0\0\0\0\x58\0\0\0\0\0\0\0\x38\x01\0\0\x12\0\x05\0\0\0\0\0\0\0\0\0\x48\0\0\0\
\0\0\0\0\x4d\x01\0\0\x12\0\x06\0\0\0\0\0\0\0\0\0\xc0\x02\0\0\0\0\0\0\x60\x01\0\
\0\x11\0\x08\0\0\0\0\0\0\0\0\0\x04\0\0\0\0\0\0\0\x85\0\0\0\x0e\0\0\0\x63\x0a\
\xfc\xff\0\0\0\0\xb7\x01\0\0\x01\0\0\0\x7b\x1a\xf0\xff\0\0\0\0\xbf\xa2\0\0\0\0\
\0\0\x07\x02\0\0\xfc\xff\xff\xff\xbf\xa3\0\0\0\0\0\0\x07\x03\0\0\xf0\xff\xff\
\xff\x18\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xb7\x04\0\0\0\0\0\0\x85\0\0\0\x02\0\0\
\0\xb7\0\0\0\0\0\0\0\x95\0\0\0\0\0\0\0\x79\x11\x08\0\0\0\0\0\x7b\x1a\xf8\xff\0\
\0\0\0\x85\0\0\0\x0e\0\0\0\x63\x0a\xf4\xff\0\0\0\0\xbf\xa2\0\0\0\0\0\0\x07\x02\
\0\0\xf4\xff\xff\xff\x18\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x85\0\0\0\x01\0\0\0\
\x15\0\x10\0\0\0\0\0\x85\0\0\0\x05\0\0\0\x7b\x0a\xe8\xff\0\0\0\0\xbf\xa2\0\0\0\
\0\0\0\x07\x02\0\0\xf8\xff\xff\xff\xbf\xa3\0\0\0\0\0\0\x07\x03\0\0\xe8\xff\xff\
\xff\x18\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xb7\x04\0\0\0\0\0\0\x85\0\0\0\x02\0\0\
\0\xb7\x01\0\0\x01\0\0\0\x18\x02\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xb7\x03\0\0\x01\0\
\0\0\xc3\x32\0\0\0\0\0\0\xc3\x12\x04\0\0\0\0\0\xb7\0\0\0\0\0\0\0\x95\0\0\0\0\0\
\0\0\x85\0\0\0\x0e\0\0\0\x63\x0a\xfc\xff\0\0\0\0\xbf\xa2\0\0\0\0\0\0\x07\x02\0\
\0\xfc\xff\xff\xff\x18\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x85\0\0\0\x03\0\0\0\xb7\
\0\0\0\0\0\0\0\x95\0\0\0\0\0\0\0\x79\x11\0\0\0\0\0\0\x7b\x1a\xf8\xff\0\0\0\0\
\x85\0\0\0\x05\0\0\0\xbf\x06\0\0\0\0\0\0\xbf\xa2\0\0\0\0\0\0\x07\x02\0\0\xf8\
\xff\xff\xff\x18\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x85\0\0\0\x01\0\0\0\x15\0\x4c\
\0\0\0\0\0\x79\x01\0\0\0\0\0\0\x1f\x16\0\0\0\0\0\0\xb7\x01\0\0\0\0\0\0\x6d\x61\
\x3f\0\0\0\0\0\x37\x06\0\0\x40\x42\x0f\0\xbf\x62\0\0\0\0\0\0\x77\x02\0\0\x20\0\
\0\0\x15\x02\x15\0\0\0\0\0\xb7\x03\0\0\x01\0\0\0\xb7\x04\0\0\x01\0\0\0\x25\x02\
\x01\0\xff\0\0\0\xb7\x04\0\0\0\0\0\0\x67\x04\0\0\x03\0\0\0\x7f\x42\0\0\0\0\0\0\
\xb7\x01\0\0\x01\0\0\0\x25\x02\x01\0\x0f\0\0\0\xb7\x01\0\0\0\0\0\0\x67\x01\0\0\
\x02\0\0\0\x7f\x12\0\0\0\0\0\0\x4f\x41\0\0\0\0\0\0\x25\x02\x01\0\x03\0\0\0\xb7\
\x03\0\0\0\0\0\0\x67\x03\0\0\x01\0\0\0\x4f\x31\0\0\0\0\0\0\x7f\x32\0\0\0\0\0\0\
\x77\x02\0\0\x01\0\0\0\x4f\x21\0\0\0\0\0\0\x07\x01\0\0\x20\0\0\0\x05\0\x1b\0\0\
\0\0\0\x67\x06\0\0\x20\0\0\0\x77\x06\0\0\x20\0\0\0\xb7\x02\0\0\x01\0\0\0\xb7\
\x03\0\0\x01\0\0\0\x25\x06\x01\0\xff\xff\0\0\xb7\x03\0\0\0\0\0\0\x67\x03\0\0\
\x04\0\0\0\x7f\x36\0\0\0\0\0\0\xb7\x01\0\0\x01\0\0\0\x25\x06\x01\0\xff\0\0\0\
\xb7\x01\0\0\0\0\0\0\x67\x01\0\0\x03\0\0\0\x7f\x16\0\0\0\0\0\0\x4f\x31\0\0\0\0\
\0\0\xb7\x03\0\0\x01\0\0\0\x25\x06\x01\0\x0f\0\0\0\xb7\x03\0\0\0\0\0\0\x67\x03\
\0\0\x02\0\0\0\x4f\x31\0\0\0\0\0\0\x7f\x36\0\0\0\0\0\0\x25\x06\x01\0\x03\0\0\0\
\xb7\x02\0\0\0\0\0\0\x67\x02\0\0\x01\0\0\0\x4f\x21\0\0\0\0\0\0\x7f\x26\0\0\0\0\
\0\0\x77\x06\0\0\x01\0\0\0\x4f\x61\0\0\0\0\0\0\x67\x01\0\0\x20\0\0\0\x77\x01\0\
\0\x20\0\0\0\xb7\x02\0\0\x13\0\0\0\x2d\x12\x01\0\0\0\0\0\xb7\x01\0\0\x13\0\0\0\
\x67\x01\0\0\x02\0\0\0\x18\x02\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x0f\x12\0\0\0\0\0\0\
\xb7\x01\0\0\x01\0\0\0\xc3\x12\x08\0\0\0\0\0\xb7\x01\0\0\xff\xff\xff\xff\x18\
\x02\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xc3\x12\0\0\0\0\0\0\xbf\xa2\0\0\0\0\0\0\x07\
\x02\0\0\xf8\xff\xff\xff\x18\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x85\0\0\0\x03\0\0\
\0\xb7\0\0\0\0\0\0\0\x95\0\0\0\0\0\0\0\x47\x50\x4c\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x40\0\0\0\0\0\0\0\x01\0\0\0\x14\0\0\0\x30\0\0\
\0\0\0\0\0\x01\0\0\0\x14\0\0\0\x80\0\0\0\0\0\0\0\x01\0\0\0\x16\0\0\0\xa8\0\0\0\
\0\0\0\0\x01\0\0\0\x17\0\0\0\x20\0\0\0\0\0\0\0\x01\0\0\0\x14\0\0\0\x30\0\0\0\0\
\0\0\0\x01\0\0\0\x16\0\0\0\x40\x02\0\0\0\0\0\0\x01\0\0\0\x17\0\0\0\x70\x02\0\0\
\0\0\0\0\x01\0\0\0\x17\0\0\0\x98\x02\0\0\0\0\0\0\x01\0\0\0\x16\0\0\0\x9f\xeb\
\x01\0\x18\0\0\0\0\0\0\0\x54\x07\0\0\x54\x07\0\0\xd6\x08\0\0\0\0\0\0\0\0\0\x02\
\x03\0\0\0\x01\0\0\0\0\0\0\x01\x04\0\0\0\x20\0\0\x01\0\0\0\0\0\0\0\x03\0\0\0\0\
\x02\0\0\0\x04\0\0\0\x01\0\0\0\x05\0\0\0\0\0\0\x01\x04\0\0\0\x20\0\0\0\0\0\0\0\
\0\0\0\x02\x06\0\0\0\0\0\0\0\0\0\0\x03\0\0\0\0\x02\0\0\0\x04\0\0\0\0\x28\0\0\0\
\0\0\0\0\0\0\x02\x08\0\0\0\x19\0\0\0\0\0\0\x08\x09\0\0\0\x1d\0\0\0\0\0\0\x08\
\x0a\0\0\0\x23\0\0\0\0\0\0\x01\x04\0\0\0\x20\0\0\0\0\0\0\0\0\0\0\x02\x0c\0\0\0\
\x30\0\0\0\0\0\0\x08\x0d\0\0\0\x34\0\0\0\0\0\0\x08\x0e\0\0\0\x3a\0\0\0\0\0\0\
\x01\x08\0\0\0\x40\0\0\0\0\0\0\0\x04\0\0\x04\x20\0\0\0\x4d\0\0\0\x01\0\0\0\0\0\
\0\0\x52\0\0\0\x05\0\0\0\x40\0\0\0\x5e\0\0\0\x07\0\0\0\x80\0\0\0\x62\0\0\0\x0b\
\0\0\0\xc0\0\0\0\x68\0\0\0\0\0\0\x0e\x0f\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\x02\x12\
\0\0\0\0\0\0\0\0\0\0\x02\x13\0\0\0\x75\0\0\0\x05\0\0\x04\x40\0\0\0\x7a\0\0\0\
\x14\0\0\0\0\0\0\0\0\0\0\0\x15\0\0\0\x40\0\0\0\0\0\0\0\x37\0\0\0\x80\x01\0\0\
\x80\0\0\0\x28\0\0\0\xa0\x01\0\0\x8a\0\0\0\x14\0\0\0\xc0\x01\0\0\x95\0\0\0\0\0\
\0\x01\x08\0\0\0\x40\0\0\0\0\0\0\0\x07\0\0\x05\x28\0\0\0\0\0\0\0\x16\0\0\0\0\0\
\0\0\0\0\0\0\x1d\0\0\0\0\0\0\0\0\0\0\0\x26\0\0\0\0\0\0\0\0\0\0\0\x2a\0\0\0\0\0\
\0\0\0\0\0\0\x2b\0\0\0\0\0\0\0\0\0\0\0\x31\0\0\0\0\0\0\0\xa3\0\0\0\x33\0\0\0\0\
\0\0\0\0\0\0\0\x04\0\0\x04\x28\0\0\0\0\0\0\0\x17\0\0\0\0\0\0\0\xb1\0\0\0\x1c\0\
\0\0\x80\0\0\0\xb9\0\0\0\x14\0\0\0\xc0\0\0\0\xbf\0\0\0\x14\0\0\0\0\x01\0\0\0\0\
\0\0\x04\0\0\x05\x10\0\0\0\xc7\0\0\0\x18\0\0\0\0\0\0\0\0\0\0\0\x1a\0\0\0\0\0\0\
\0\xcb\0\0\0\x18\0\0\0\0\0\0\0\xd6\0\0\0\x18\0\0\0\0\0\0\0\xdf\0\0\0\x02\0\0\
\x04\x10\0\0\0\xe9\0\0\0\x19\0\0\0\0\0\0\0\xee\0\0\0\x19\0\0\0\x40\0\0\0\0\0\0\
\0\0\0\0\x02\x18\0\0\0\0\0\0\0\x02\0\0\x04\x10\0\0\0\xf3\0\0\0\x1b\0\0\0\0\0\0\
\0\xfc\0\0\0\x0a\0\0\0\x40\0\0\0\0\0\0\0\0\0\0\x02\0\0\0\0\0\0\0\0\0\0\0\x02\
\x46\0\0\0\0\0\0\0\x05\0\0\x04\x28\0\0\0\x08\x01\0\0\x14\0\0\0\0\0\0\0\x11\x01\
\0\0\x1e\0\0\0\x40\0\0\0\x14\x01\0\0\x14\0\0\0\x80\0\0\0\x24\x01\0\0\x14\0\0\0\
\xc0\0\0\0\0\0\0\0\x1f\0\0\0\0\x01\0\0\0\0\0\0\0\0\0\x02\x49\0\0\0\0\0\0\0\x02\
\0\0\x05\x08\0\0\0\x2d\x01\0\0\x14\0\0\0\0\0\0\0\x3c\x01\0\0\x20\0\0\0\0\0\0\0\
\x4a\x01\0\0\0\0\0\x08\x21\0\0\0\x58\x01\0\0\0\0\0\x08\x22\0\0\0\0\0\0\0\x01\0\
\0\x04\x08\0\0\0\x63\x01\0\0\x23\0\0\0\0\0\0\0\x6b\x01\0\0\0\0\0\x08\x24\0\0\0\
\x6f\x01\0\0\0\0\0\x08\x25\0\0\0\x75\x01\0\0\0\0\0\x01\x08\0\0\0\x40\0\0\x01\0\
\0\0\0\x06\0\0\x04\x18\0\0\0\x7f\x01\0\0\x14\0\0\0\0\0\0\0\x8d\x01\0\0\x27\0\0\
\0\x40\0\0\0\x9b\x01\0\0\x27\0\0\0\x48\0\0\0\xaa\x01\0\0\x28\0\0\0\x60\0\0\0\
\xbc\x01\0\0\x28\0\0\0\x80\0\0\0\xce\x01\0\0\x0a\0\0\0\xa0\0\0\0\xda\x01\0\0\0\
\0\0\x01\x01\0\0\0\x08\0\0\0\xe8\x01\0\0\0\0\0\x08\x29\0\0\0\0\0\0\0\x01\0\0\
\x04\x04\0\0\0\x63\x01\0\0\x02\0\0\0\0\0\0\0\0\0\0\0\x03\0\0\x04\x20\0\0\0\xf1\
\x01\0\0\x14\0\0\0\0\0\0\0\x01\x02\0\0\x14\0\0\0\x40\0\0\0\x11\x02\0\0\x18\0\0\
\0\x80\0\0\0\0\0\0\0\x05\0\0\x04\x28\0\0\0\x1f\x02\0\0\x14\0\0\0\0\0\0\0\x29\
\x02\0\0\x2c\0\0\0\x40\0\0\0\x36\x02\0\0\x14\0\0\0\x80\0\0\0\0\0\0\0\x2d\0\0\0\
\xc0\0\0\0\x40\x02\0\0\x2f\0\0\0\0\x01\0\0\x44\x02\0\0\0\0\0\x08\x12\0\0\0\0\0\
\0\0\x02\0\0\x05\x08\0\0\0\x4e\x02\0\0\x2e\0\0\0\0\0\0\0\x54\x02\0\0\x28\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\x02\x48\0\0\0\0\0\0\0\0\0\0\x02\x30\0\0\0\x65\x02\0\0\0\
\0\0\x08\x4a\0\0\0\0\0\0\0\x02\0\0\x04\x10\0\0\0\x70\x02\0\0\x32\0\0\0\0\0\0\0\
\x76\x02\0\0\x1b\0\0\0\x40\0\0\0\0\0\0\0\0\0\0\x02\x47\0\0\0\xa3\0\0\0\x02\0\0\
\x04\x10\0\0\0\xe9\0\0\0\x34\0\0\0\0\0\0\0\x87\x02\0\0\x35\0\0\0\x40\0\0\0\0\0\
\0\0\0\0\0\x02\x33\0\0\0\0\0\0\0\0\0\0\x02\x36\0\0\0\0\0\0\0\x01\0\0\x0d\0\0\0\
\0\0\0\0\0\x34\0\0\0\0\0\0\0\x02\0\0\x05\x04\0\0\0\x8c\x02\0\0\x28\0\0\0\0\0\0\
\0\x96\x02\0\0\x0a\0\0\0\0\0\0\0\0\0\0\0\x04\0\0\x04\x20\0\0\0\x4d\0\0\0\x01\0\
\0\0\0\0\0\0\x52\0\0\0\x05\0\0\0\x40\0\0\0\x5e\0\0\0\x11\0\0\0\x80\0\0\0\x62\0\
\0\0\x0b\0\0\0\xc0\0\0\0\xa0\x02\0\0\0\0\0\x0e\x38\0\0\0\x01\0\0\0\0\0\0\0\0\0\
\0\x02\x0e\0\0\0\0\0\0\0\x01\0\0\x0d\x02\0\0\0\xa6\x02\0\0\x3a\0\0\0\xaa\x02\0\
\0\x01\0\0\x0c\x3b\0\0\0\xbb\x02\0\0\x01\0\0\x0c\x3b\0\0\0\xd0\x02\0\0\x01\0\0\
\x0c\x3b\0\0\0\xe5\x02\0\0\x01\0\0\x0c\x3b\0\0\0\xf8\x02\0\0\x03\0\0\x04\x58\0\
\0\0\xfd\x02\0\0\x09\0\0\0\0\0\0\0\x04\x03\0\0\x09\0\0\0\x20\0\0\0\x0a\x03\0\0\
\x41\0\0\0\x40\0\0\0\0\0\0\0\0\0\0\x03\0\0\0\0\x09\0\0\0\x04\0\0\0\x14\0\0\0\
\xf8\x02\0\0\0\0\0\x0e\x40\0\0\0\x01\0\0\0\x10\x03\0\0\0\0\0\x01\x01\0\0\0\x08\
\0\0\x01\0\0\0\0\0\0\0\x03\0\0\0\0\x43\0\0\0\x04\0\0\0\x04\0\0\0\x15\x03\0\0\0\
\0\0\x0e\x44\0\0\0\x01\0\0\0\x1d\x03\0\0\0\0\0\x07\0\0\0\0\x2b\x03\0\0\0\0\0\
\x07\0\0\0\0\x37\x03\0\0\0\0\0\x07\0\0\0\0\x41\x03\0\0\0\0\0\x07\0\0\0\0\x4b\
\x03\0\0\0\0\0\x07\0\0\0\0\x61\x08\0\0\x01\0\0\x0f\x58\0\0\0\x42\0\0\0\0\0\0\0\
\x58\0\0\0\x66\x08\0\0\x01\0\0\x0f\x04\0\0\0\x45\0\0\0\0\0\0\0\x04\0\0\0\x6e\
\x08\0\0\x02\0\0\x0f\x40\0\0\0\x10\0\0\0\0\0\0\0\x20\0\0\0\x39\0\0\0\x20\0\0\0\
\x20\0\0\0\0\x69\x6e\x74\0\x5f\x5f\x41\x52\x52\x41\x59\x5f\x53\x49\x5a\x45\x5f\
\x54\x59\x50\x45\x5f\x5f\0\x75\x33\x32\0\x5f\x5f\x75\x33\x32\0\x75\x6e\x73\x69\
\x67\x6e\x65\x64\x20\x69\x6e\x74\0\x75\x36\x34\0\x5f\x5f\x75\x36\x34\0\x75\x6e\
\x73\x69\x67\x6e\x65\x64\x20\x6c\x6f\x6e\x67\x20\x6c\x6f\x6e\x67\0\x74\x79\x70\
\x65\0\x6d\x61\x78\x5f\x65\x6e\x74\x72\x69\x65\x73\0\x6b\x65\x79\0\x76\x61\x6c\
\x75\x65\0\x69\x6e\x5f\x72\x65\x61\x64\x61\x68\x65\x61\x64\0\x70\x61\x67\x65\0\
\x66\x6c\x61\x67\x73\0\x5f\x72\x65\x66\x63\x6f\x75\x6e\x74\0\x6d\x65\x6d\x63\
\x67\x5f\x64\x61\x74\x61\0\x75\x6e\x73\x69\x67\x6e\x65\x64\x20\x6c\x6f\x6e\x67\
\0\x63\x61\x6c\x6c\x62\x61\x63\x6b\x5f\x68\x65\x61\x64\0\x6d\x61\x70\x70\x69\
\x6e\x67\0\x69\x6e\x64\x65\x78\0\x70\x72\x69\x76\x61\x74\x65\0\x6c\x72\x75\0\
\x62\x75\x64\x64\x79\x5f\x6c\x69\x73\x74\0\x70\x63\x70\x5f\x6c\x69\x73\x74\0\
\x6c\x69\x73\x74\x5f\x68\x65\x61\x64\0\x6e\x65\x78\x74\0\x70\x72\x65\x76\0\x5f\
\x5f\x66\x69\x6c\x6c\x65\x72\0\x6d\x6c\x6f\x63\x6b\x5f\x63\x6f\x75\x6e\x74\0\
\x70\x70\x5f\x6d\x61\x67\x69\x63\0\x70\x70\0\x5f\x70\x70\x5f\x6d\x61\x70\x70\
\x69\x6e\x67\x5f\x70\x61\x64\0\x64\x6d\x61\x5f\x61\x64\x64\x72\0\x64\x6d\x61\
\x5f\x61\x64\x64\x72\x5f\x75\x70\x70\x65\x72\0\x70\x70\x5f\x66\x72\x61\x67\x5f\
\x63\x6f\x75\x6e\x74\0\x61\x74\x6f\x6d\x69\x63\x5f\x6c\x6f\x6e\x67\x5f\x74\0\
\x61\x74\x6f\x6d\x69\x63\x36\x34\x5f\x74\0\x63\x6f\x75\x6e\x74\x65\x72\0\x73\
\x36\x34\0\x5f\x5f\x73\x36\x34\0\x6c\x6f\x6e\x67\x20\x6c\x6f\x6e\x67\0\x63\x6f\
\x6d\x70\x6f\x75\x6e\x64\x5f\x68\x65\x61\x64\0\x63\x6f\x6d\x70\x6f\x75\x6e\x64\
\x5f\x64\x74\x6f\x72\0\x63\x6f\x6d\x70\x6f\x75\x6e\x64\x5f\x6f\x72\x64\x65\x72\
\0\x63\x6f\x6d\x70\x6f\x75\x6e\x64\x5f\x6d\x61\x70\x63\x6f\x75\x6e\x74\0\x63\
\x6f\x6d\x70\x6f\x75\x6e\x64\x5f\x70\x69\x6e\x63\x6f\x75\x6e\x74\0\x63\x6f\x6d\
\x70\x6f\x75\x6e\x64\x5f\x6e\x72\0\x75\x6e\x73\x69\x67\x6e\x65\x64\x20\x63\x68\
\x61\x72\0\x61\x74\x6f\x6d\x69\x63\x5f\x74\0\x5f\x63\x6f\x6d\x70\x6f\x75\x6e\
\x64\x5f\x70\x61\x64\x5f\x31\0\x5f\x63\x6f\x6d\x70\x6f\x75\x6e\x64\x5f\x70\x61\
\x64\x5f\x32\0\x64\x65\x66\x65\x72\x72\x65\x64\x5f\x6c\x69\x73\x74\0\x5f\x70\
\x74\x5f\x70\x61\x64\x5f\x31\0\x70\x6d\x64\x5f\x68\x75\x67\x65\x5f\x70\x74\x65\
\0\x5f\x70\x74\x5f\x70\x61\x64\x5f\x32\0\x70\x74\x6c\0\x70\x67\x74\x61\x62\x6c\
\x65\x5f\x74\0\x70\x74\x5f\x6d\x6d\0\x70\x74\x5f\x66\x72\x61\x67\x5f\x72\x65\
\x66\x63\x6f\x75\x6e\x74\0\x73\x70\x69\x6e\x6c\x6f\x63\x6b\x5f\x74\0\x70\x67\
\x6d\x61\x70\0\x7a\x6f\x6e\x65\x5f\x64\x65\x76\x69\x63\x65\x5f\x64\x61\x74\x61\
\0\x66\x75\x6e\x63\0\x5f\x6d\x61\x70\x63\x6f\x75\x6e\x74\0\x70\x61\x67\x65\x5f\
\x74\x79\x70\x65\0\x62\x69\x72\x74\x68\0\x63\x74\x78\0\x64\x6f\x5f\x70\x61\x67\
\x65\x5f\x63\x61\x63\x68\x65\x5f\x72\x61\0\x70\x61\x67\x65\x5f\x63\x61\x63\x68\
\x65\x5f\x61\x6c\x6c\x6f\x63\x5f\x72\x65\x74\0\x64\x6f\x5f\x70\x61\x67\x65\x5f\
\x63\x61\x63\x68\x65\x5f\x72\x61\x5f\x72\x65\x74\0\x6d\x61\x72\x6b\x5f\x70\x61\
\x67\x65\x5f\x61\x63\x63\x65\x73\x73\x65\x64\0\x68\x69\x73\x74\0\x75\x6e\x75\
\x73\x65\x64\0\x74\x6f\x74\x61\x6c\0\x73\x6c\x6f\x74\x73\0\x63\x68\x61\x72\0\
\x4c\x49\x43\x45\x4e\x53\x45\0\x61\x64\x64\x72\x65\x73\x73\x5f\x73\x70\x61\x63\
\x65\0\x64\x65\x76\x5f\x70\x61\x67\x65\x6d\x61\x70\0\x6d\x6d\x5f\x73\x74\x72\
\x75\x63\x74\0\x70\x61\x67\x65\x5f\x70\x6f\x6f\x6c\0\x73\x70\x69\x6e\x6c\x6f\
\x63\x6b\0\x2f\x68\x6f\x6d\x65\x2f\x72\x65\x76\x65\x72\x63\x63\x71\x69\x6e\x2f\
\x65\x62\x70\x66\x2f\x6c\x69\x62\x62\x70\x66\x2d\x62\x6f\x6f\x74\x73\x74\x72\
\x61\x70\x2d\x66\x6f\x72\x2d\x61\x6e\x64\x72\x6f\x69\x64\x2f\x6c\x69\x62\x62\
\x70\x66\x2d\x74\x6f\x6f\x6c\x73\x2f\x72\x65\x61\x64\x61\x68\x65\x61\x64\x2e\
\x62\x70\x66\x2e\x63\0\x09\x75\x33\x32\x20\x70\x69\x64\x20\x3d\x20\x62\x70\x66\
\x5f\x67\x65\x74\x5f\x63\x75\x72\x72\x65\x6e\x74\x5f\x70\x69\x64\x5f\x74\x67\
\x69\x64\x28\x29\x3b\0\x09\x75\x36\x34\x20\x6f\x6e\x65\x20\x3d\x20\x31\x3b\0\
\x09\x62\x70\x66\x5f\x6d\x61\x70\x5f\x75\x70\x64\x61\x74\x65\x5f\x65\x6c\x65\
\x6d\x28\x26\x69\x6e\x5f\x72\x65\x61\x64\x61\x68\x65\x61\x64\x2c\x20\x26\x70\
\x69\x64\x2c\x20\x26\x6f\x6e\x65\x2c\x20\x30\x29\x3b\0\x69\x6e\x74\x20\x42\x50\
\x46\x5f\x50\x52\x4f\x47\x28\x64\x6f\x5f\x70\x61\x67\x65\x5f\x63\x61\x63\x68\
\x65\x5f\x72\x61\x29\0\x69\x6e\x74\x20\x42\x50\x46\x5f\x50\x52\x4f\x47\x28\x70\
\x61\x67\x65\x5f\x63\x61\x63\x68\x65\x5f\x61\x6c\x6c\x6f\x63\x5f\x72\x65\x74\
\x2c\x20\x67\x66\x70\x5f\x74\x20\x67\x66\x70\x2c\x20\x73\x74\x72\x75\x63\x74\
\x20\x70\x61\x67\x65\x20\x2a\x72\x65\x74\x29\0\x09\x69\x66\x20\x28\x21\x62\x70\
\x66\x5f\x6d\x61\x70\x5f\x6c\x6f\x6f\x6b\x75\x70\x5f\x65\x6c\x65\x6d\x28\x26\
\x69\x6e\x5f\x72\x65\x61\x64\x61\x68\x65\x61\x64\x2c\x20\x26\x70\x69\x64\x29\
\x29\0\x09\x74\x73\x20\x3d\x20\x62\x70\x66\x5f\x6b\x74\x69\x6d\x65\x5f\x67\x65\
\x74\x5f\x6e\x73\x28\x29\x3b\0\x09\x62\x70\x66\x5f\x6d\x61\x70\x5f\x75\x70\x64\
\x61\x74\x65\x5f\x65\x6c\x65\x6d\x28\x26\x62\x69\x72\x74\x68\x2c\x20\x26\x72\
\x65\x74\x2c\x20\x26\x74\x73\x2c\x20\x30\x29\x3b\0\x09\x5f\x5f\x73\x79\x6e\x63\
\x5f\x66\x65\x74\x63\x68\x5f\x61\x6e\x64\x5f\x61\x64\x64\x28\x26\x68\x69\x73\
\x74\x2e\x75\x6e\x75\x73\x65\x64\x2c\x20\x31\x29\x3b\0\x09\x5f\x5f\x73\x79\x6e\
\x63\x5f\x66\x65\x74\x63\x68\x5f\x61\x6e\x64\x5f\x61\x64\x64\x28\x26\x68\x69\
\x73\x74\x2e\x74\x6f\x74\x61\x6c\x2c\x20\x31\x29\x3b\0\x09\x62\x70\x66\x5f\x6d\
\x61\x70\x5f\x64\x65\x6c\x65\x74\x65\x5f\x65\x6c\x65\x6d\x28\x26\x69\x6e\x5f\
\x72\x65\x61\x64\x61\x68\x65\x61\x64\x2c\x20\x26\x70\x69\x64\x29\x3b\0\x69\x6e\
\x74\x20\x42\x50\x46\x5f\x50\x52\x4f\x47\x28\x64\x6f\x5f\x70\x61\x67\x65\x5f\
\x63\x61\x63\x68\x65\x5f\x72\x61\x5f\x72\x65\x74\x29\0\x69\x6e\x74\x20\x42\x50\
\x46\x5f\x50\x52\x4f\x47\x28\x6d\x61\x72\x6b\x5f\x70\x61\x67\x65\x5f\x61\x63\
\x63\x65\x73\x73\x65\x64\x2c\x20\x73\x74\x72\x75\x63\x74\x20\x70\x61\x67\x65\
\x20\x2a\x70\x61\x67\x65\x29\0\x09\x75\x36\x34\x20\x2a\x74\x73\x70\x2c\x20\x73\
\x6c\x6f\x74\x2c\x20\x74\x73\x20\x3d\x20\x62\x70\x66\x5f\x6b\x74\x69\x6d\x65\
\x5f\x67\x65\x74\x5f\x6e\x73\x28\x29\x3b\0\x09\x74\x73\x70\x20\x3d\x20\x62\x70\
\x66\x5f\x6d\x61\x70\x5f\x6c\x6f\x6f\x6b\x75\x70\x5f\x65\x6c\x65\x6d\x28\x26\
\x62\x69\x72\x74\x68\x2c\x20\x26\x70\x61\x67\x65\x29\x3b\0\x09\x69\x66\x20\x28\
\x21\x74\x73\x70\x29\0\x09\x64\x65\x6c\x74\x61\x20\x3d\x20\x28\x73\x36\x34\x29\
\x28\x74\x73\x20\x2d\x20\x2a\x74\x73\x70\x29\x3b\0\x09\x69\x66\x20\x28\x64\x65\
\x6c\x74\x61\x20\x3c\x20\x30\x29\0\x09\x73\x6c\x6f\x74\x20\x3d\x20\x6c\x6f\x67\
\x32\x6c\x28\x64\x65\x6c\x74\x61\x20\x2f\x20\x31\x30\x30\x30\x30\x30\x30\x55\
\x29\x3b\0\x2f\x68\x6f\x6d\x65\x2f\x72\x65\x76\x65\x72\x63\x63\x71\x69\x6e\x2f\
\x65\x62\x70\x66\x2f\x6c\x69\x62\x62\x70\x66\x2d\x62\x6f\x6f\x74\x73\x74\x72\
\x61\x70\x2d\x66\x6f\x72\x2d\x61\x6e\x64\x72\x6f\x69\x64\x2f\x6c\x69\x62\x62\
\x70\x66\x2d\x74\x6f\x6f\x6c\x73\x2f\x2e\x2f\x62\x69\x74\x73\x2e\x62\x70\x66\
\x2e\x68\0\x09\x75\x33\x32\x20\x68\x69\x20\x3d\x20\x76\x20\x3e\x3e\x20\x33\x32\
\x3b\0\x09\x69\x66\x20\x28\x68\x69\x29\0\x09\x73\x68\x69\x66\x74\x20\x3d\x20\
\x28\x76\x20\x3e\x20\x30\x78\x46\x46\x29\x20\x3c\x3c\x20\x33\x3b\x20\x76\x20\
\x3e\x3e\x3d\x20\x73\x68\x69\x66\x74\x3b\x20\x72\x20\x7c\x3d\x20\x73\x68\x69\
\x66\x74\x3b\0\x09\x73\x68\x69\x66\x74\x20\x3d\x20\x28\x76\x20\x3e\x20\x30\x78\
\x46\x29\x20\x3c\x3c\x20\x32\x3b\x20\x76\x20\x3e\x3e\x3d\x20\x73\x68\x69\x66\
\x74\x3b\x20\x72\x20\x7c\x3d\x20\x73\x68\x69\x66\x74\x3b\0\x09\x73\x68\x69\x66\
\x74\x20\x3d\x20\x28\x76\x20\x3e\x20\x30\x78\x33\x29\x20\x3c\x3c\x20\x31\x3b\
\x20\x76\x20\x3e\x3e\x3d\x20\x73\x68\x69\x66\x74\x3b\x20\x72\x20\x7c\x3d\x20\
\x73\x68\x69\x66\x74\x3b\0\x09\x72\x20\x7c\x3d\x20\x28\x76\x20\x3e\x3e\x20\x31\
\x29\x3b\0\x09\x09\x72\x65\x74\x75\x72\x6e\x20\x6c\x6f\x67\x32\x28\x68\x69\x29\
\x20\x2b\x20\x33\x32\x3b\0\x09\x09\x72\x65\x74\x75\x72\x6e\x20\x6c\x6f\x67\x32\
\x28\x76\x29\x3b\0\x09\x72\x20\x3d\x20\x28\x76\x20\x3e\x20\x30\x78\x46\x46\x46\
\x46\x29\x20\x3c\x3c\x20\x34\x3b\x20\x76\x20\x3e\x3e\x3d\x20\x72\x3b\0\x09\x69\
\x66\x20\x28\x73\x6c\x6f\x74\x20\x3e\x3d\x20\x4d\x41\x58\x5f\x53\x4c\x4f\x54\
\x53\x29\0\x09\x5f\x5f\x73\x79\x6e\x63\x5f\x66\x65\x74\x63\x68\x5f\x61\x6e\x64\
\x5f\x61\x64\x64\x28\x26\x68\x69\x73\x74\x2e\x73\x6c\x6f\x74\x73\x5b\x73\x6c\
\x6f\x74\x5d\x2c\x20\x31\x29\x3b\0\x09\x5f\x5f\x73\x79\x6e\x63\x5f\x66\x65\x74\
\x63\x68\x5f\x61\x6e\x64\x5f\x61\x64\x64\x28\x26\x68\x69\x73\x74\x2e\x75\x6e\
\x75\x73\x65\x64\x2c\x20\x2d\x31\x29\x3b\0\x75\x70\x64\x61\x74\x65\x5f\x61\x6e\
\x64\x5f\x63\x6c\x65\x61\x6e\x75\x70\x3a\0\x09\x62\x70\x66\x5f\x6d\x61\x70\x5f\
\x64\x65\x6c\x65\x74\x65\x5f\x65\x6c\x65\x6d\x28\x26\x62\x69\x72\x74\x68\x2c\
\x20\x26\x70\x61\x67\x65\x29\x3b\0\x2e\x62\x73\x73\0\x6c\x69\x63\x65\x6e\x73\
\x65\0\x2e\x6d\x61\x70\x73\0\x66\x65\x6e\x74\x72\x79\x2f\x64\x6f\x5f\x70\x61\
\x67\x65\x5f\x63\x61\x63\x68\x65\x5f\x72\x61\0\x66\x65\x78\x69\x74\x2f\x5f\x5f\
\x70\x61\x67\x65\x5f\x63\x61\x63\x68\x65\x5f\x61\x6c\x6c\x6f\x63\0\x66\x65\x78\
\x69\x74\x2f\x64\x6f\x5f\x70\x61\x67\x65\x5f\x63\x61\x63\x68\x65\x5f\x72\x61\0\
\x66\x65\x6e\x74\x72\x79\x2f\x6d\x61\x72\x6b\x5f\x70\x61\x67\x65\x5f\x61\x63\
\x63\x65\x73\x73\x65\x64\0\0\0\0\0\0\0\x9f\xeb\x01\0\x20\0\0\0\0\0\0\0\x44\0\0\
\0\x44\0\0\0\x94\x04\0\0\xd8\x04\0\0\0\0\0\0\x08\0\0\0\x74\x08\0\0\x01\0\0\0\0\
\0\0\0\x3c\0\0\0\x8c\x08\0\0\x01\0\0\0\0\0\0\0\x3d\0\0\0\xa5\x08\0\0\x01\0\0\0\
\0\0\0\0\x3e\0\0\0\xbc\x08\0\0\x01\0\0\0\0\0\0\0\x3f\0\0\0\x10\0\0\0\x74\x08\0\
\0\x06\0\0\0\0\0\0\0\x54\x03\0\0\xa4\x03\0\0\x0c\x78\0\0\x08\0\0\0\x54\x03\0\0\
\xa4\x03\0\0\x06\x78\0\0\x18\0\0\0\x54\x03\0\0\xcb\x03\0\0\x06\x7c\0\0\x28\0\0\
\0\x54\x03\0\0\0\0\0\0\0\0\0\0\x40\0\0\0\x54\x03\0\0\xd9\x03\0\0\x02\x84\0\0\
\x60\0\0\0\x54\x03\0\0\x0d\x04\0\0\x05\x70\0\0\x8c\x08\0\0\x0d\0\0\0\0\0\0\0\
\x54\x03\0\0\x2c\x04\0\0\x05\x98\0\0\x10\0\0\0\x54\x03\0\0\xa4\x03\0\0\x0c\xa0\
\0\0\x18\0\0\0\x54\x03\0\0\xa4\x03\0\0\x06\xa0\0\0\x28\0\0\0\x54\x03\0\0\0\0\0\
\0\0\0\0\0\x30\0\0\0\x54\x03\0\0\x6c\x04\0\0\x07\xac\0\0\x48\0\0\0\x54\x03\0\0\
\x6c\x04\0\0\x06\xac\0\0\x50\0\0\0\x54\x03\0\0\x9c\x04\0\0\x07\xb8\0\0\x58\0\0\
\0\x54\x03\0\0\x9c\x04\0\0\x05\xb8\0\0\x68\0\0\0\x54\x03\0\0\x9c\x04\0\0\x07\
\xb8\0\0\x80\0\0\0\x54\x03\0\0\xb6\x04\0\0\x02\xbc\0\0\xa8\0\0\0\x54\x03\0\0\
\xe2\x04\0\0\x02\xc0\0\0\xc8\0\0\0\x54\x03\0\0\x0a\x05\0\0\x02\xc4\0\0\xd0\0\0\
\0\x54\x03\0\0\x2c\x04\0\0\x05\x98\0\0\xa5\x08\0\0\x05\0\0\0\0\0\0\0\x54\x03\0\
\0\xa4\x03\0\0\x0c\xe4\0\0\x08\0\0\0\x54\x03\0\0\xa4\x03\0\0\x06\xe4\0\0\x18\0\
\0\0\x54\x03\0\0\0\0\0\0\0\0\0\0\x20\0\0\0\x54\x03\0\0\x31\x05\0\0\x02\xec\0\0\
\x38\0\0\0\x54\x03\0\0\x5c\x05\0\0\x05\xdc\0\0\xbc\x08\0\0\x2f\0\0\0\0\0\0\0\
\x54\x03\0\0\x7f\x05\0\0\x05\0\x01\0\x10\0\0\0\x54\x03\0\0\xb3\x05\0\0\x17\x08\
\x01\0\x28\0\0\0\x54\x03\0\0\0\0\0\0\0\0\0\0\x30\0\0\0\x54\x03\0\0\xdd\x05\0\0\
\x08\x14\x01\0\x48\0\0\0\x54\x03\0\0\x08\x06\0\0\x06\x18\x01\0\x50\0\0\0\x54\
\x03\0\0\x13\x06\0\0\x15\x20\x01\0\x58\0\0\0\x54\x03\0\0\x13\x06\0\0\x13\x20\
\x01\0\x68\0\0\0\x54\x03\0\0\x2e\x06\0\0\x06\x24\x01\0\x70\0\0\0\x54\x03\0\0\
\x3e\x06\0\0\x15\x2c\x01\0\x78\0\0\0\x5f\x06\0\0\xac\x06\0\0\x0d\x5c\0\0\x88\0\
\0\0\x5f\x06\0\0\xbf\x06\0\0\x06\x64\0\0\xa0\0\0\0\x5f\x06\0\0\xac\x06\0\0\x0b\
\x5c\0\0\xb0\0\0\0\x5f\x06\0\0\xc8\x06\0\0\x15\x34\0\0\xb8\0\0\0\x5f\x06\0\0\
\xc8\x06\0\0\x1d\x34\0\0\xd8\0\0\0\x5f\x06\0\0\xfb\x06\0\0\x14\x38\0\0\xe0\0\0\
\0\x5f\x06\0\0\xfb\x06\0\0\x1c\x38\0\0\xe8\0\0\0\x5f\x06\0\0\xfb\x06\0\0\x29\
\x38\0\0\xf0\0\0\0\x5f\x06\0\0\xfb\x06\0\0\x1c\x38\0\0\0\x01\0\0\x5f\x06\0\0\
\x2d\x07\0\0\x14\x3c\0\0\x08\x01\0\0\x5f\x06\0\0\x2d\x07\0\0\x29\x3c\0\0\x10\
\x01\0\0\x5f\x06\0\0\x2d\x07\0\0\x1c\x3c\0\0\x18\x01\0\0\x5f\x06\0\0\x5f\x07\0\
\0\x0a\x40\0\0\x20\x01\0\0\x5f\x06\0\0\x5f\x07\0\0\x04\x40\0\0\x28\x01\0\0\x5f\
\x06\0\0\x6f\x07\0\0\x13\x68\0\0\x38\x01\0\0\x5f\x06\0\0\x87\x07\0\0\x0f\x70\0\
\0\x68\x01\0\0\x5f\x06\0\0\x99\x07\0\0\x13\x30\0\0\x70\x01\0\0\x5f\x06\0\0\x99\
\x07\0\0\x1b\x30\0\0\x90\x01\0\0\x5f\x06\0\0\xc8\x06\0\0\x15\x34\0\0\x98\x01\0\
\0\x5f\x06\0\0\xc8\x06\0\0\x1d\x34\0\0\xa0\x01\0\0\x5f\x06\0\0\xc8\x06\0\0\x2a\
\x34\0\0\xb0\x01\0\0\x5f\x06\0\0\xc8\x06\0\0\x1d\x34\0\0\xc0\x01\0\0\x5f\x06\0\
\0\xfb\x06\0\0\x14\x38\0\0\xc8\x01\0\0\x5f\x06\0\0\xfb\x06\0\0\x29\x38\0\0\xd0\
\x01\0\0\x5f\x06\0\0\xfb\x06\0\0\x1c\x38\0\0\xe8\x01\0\0\x5f\x06\0\0\x2d\x07\0\
\0\x14\x3c\0\0\xf0\x01\0\0\x5f\x06\0\0\x2d\x07\0\0\x29\x3c\0\0\xf8\x01\0\0\x5f\
\x06\0\0\x2d\x07\0\0\x1c\x3c\0\0\0\x02\0\0\x5f\x06\0\0\x5f\x07\0\0\x0a\x40\0\0\
\x08\x02\0\0\x5f\x06\0\0\x5f\x07\0\0\x04\x40\0\0\x10\x02\0\0\x5f\x06\0\0\0\0\0\
\0\0\0\0\0\x28\x02\0\0\x54\x03\0\0\xba\x07\0\0\x06\x30\x01\0\x38\x02\0\0\x54\
\x03\0\0\xd2\x07\0\0\x18\x38\x01\0\x60\x02\0\0\x54\x03\0\0\xd2\x07\0\0\x02\x38\
\x01\0\x70\x02\0\0\x54\x03\0\0\xff\x07\0\0\x02\x44\x01\0\x90\x02\0\0\x54\x03\0\
\0\x28\x08\0\0\x01\x40\x01\0\x98\x02\0\0\x54\x03\0\0\x3c\x08\0\0\x02\x48\x01\0\
\xb0\x02\0\0\x54\x03\0\0\x7f\x05\0\0\x05\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\x01\0\0\0\x03\0\0\0\x20\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x40\
\0\0\0\0\0\0\0\xe8\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\
\0\0\0\x09\0\0\0\x02\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x28\x02\0\0\0\0\0\0\
\x88\x02\0\0\0\0\0\0\x01\0\0\0\0\0\0\0\x08\0\0\0\0\0\0\0\x18\0\0\0\0\0\0\0\x11\
\0\0\0\x01\0\0\0\x06\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xb0\x04\0\0\0\0\0\0\x70\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\x08\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x29\0\0\0\x01\0\0\
\0\x06\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x20\x05\0\0\0\0\0\0\xe0\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\x08\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x42\0\0\0\x01\0\0\0\x06\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\x06\0\0\0\0\0\0\x48\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x08\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x59\0\0\0\x01\0\0\0\x06\0\0\0\0\0\0\0\0\0\0\0\0\
\0\0\0\x48\x06\0\0\0\0\0\0\xc0\x02\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x08\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\x73\0\0\0\x08\0\0\0\x03\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x08\
\x09\0\0\0\0\0\0\x58\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x04\0\0\0\0\0\0\0\0\0\0\0\0\
\0\0\0\x78\0\0\0\x01\0\0\0\x03\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x08\x09\0\0\0\0\0\
\0\x04\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x80\0\0\
\0\x01\0\0\0\x03\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x10\x09\0\0\0\0\0\0\x40\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\x08\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x68\x01\0\0\x09\0\0\0\
\x40\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x50\x09\0\0\0\0\0\0\x10\0\0\0\0\0\0\0\x02\0\
\0\0\x03\0\0\0\x08\0\0\0\0\0\0\0\x10\0\0\0\0\0\0\0\x84\x01\0\0\x09\0\0\0\x40\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x60\x09\0\0\0\0\0\0\x30\0\0\0\0\0\0\0\x02\0\0\0\
\x04\0\0\0\x08\0\0\0\0\0\0\0\x10\0\0\0\0\0\0\0\xa1\x01\0\0\x09\0\0\0\x40\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\x90\x09\0\0\0\0\0\0\x10\0\0\0\0\0\0\0\x02\0\0\0\x05\0\
\0\0\x08\0\0\0\0\0\0\0\x10\0\0\0\0\0\0\0\xbc\x01\0\0\x09\0\0\0\x40\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\xa0\x09\0\0\0\0\0\0\x40\0\0\0\0\0\0\0\x02\0\0\0\x06\0\0\0\
\x08\0\0\0\0\0\0\0\x10\0\0\0\0\0\0\0\xda\x01\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\xe0\x09\0\0\0\0\0\0\x42\x10\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x08\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\xdf\x01\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\x28\x1a\0\0\0\0\0\0\xf8\x04\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x08\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0";

	*sz = sizeof(data) - 1;
	return (const void *)data;
}

#ifdef __cplusplus
struct readahead_bpf *readahead_bpf::open(const struct bpf_object_open_opts *opts) { return readahead_bpf__open_opts(opts); }
struct readahead_bpf *readahead_bpf::open_and_load() { return readahead_bpf__open_and_load(); }
int readahead_bpf::load(struct readahead_bpf *skel) { return readahead_bpf__load(skel); }
int readahead_bpf::attach(struct readahead_bpf *skel) { return readahead_bpf__attach(skel); }
void readahead_bpf::detach(struct readahead_bpf *skel) { readahead_bpf__detach(skel); }
void readahead_bpf::destroy(struct readahead_bpf *skel) { readahead_bpf__destroy(skel); }
const void *readahead_bpf::elf_bytes(size_t *sz) { return readahead_bpf__elf_bytes(sz); }
#endif /* __cplusplus */

__attribute__((unused)) static void
readahead_bpf__assert(struct readahead_bpf *s __attribute__((unused)))
{
#ifdef __cplusplus
#define _Static_assert static_assert
#endif
	_Static_assert(sizeof(s->bss->hist) == 88, "unexpected size of 'hist'");
#ifdef __cplusplus
#undef _Static_assert
#endif
}

#endif /* __READAHEAD_BPF_SKEL_H__ */
