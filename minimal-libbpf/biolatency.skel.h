/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */

/* THIS FILE IS AUTOGENERATED BY BPFTOOL! */
#ifndef __BIOLATENCY_BPF_SKEL_H__
#define __BIOLATENCY_BPF_SKEL_H__

#include <errno.h>
#include <stdlib.h>
#include <bpf/libbpf.h>

struct biolatency_bpf {
	struct bpf_object_skeleton *skeleton;
	struct bpf_object *obj;
	struct {
		struct bpf_map *start;
		struct bpf_map *hists;
		struct bpf_map *bss;
	} maps;
	struct {
		struct bpf_program *block_rq_insert_btf;
		struct bpf_program *block_rq_complete_btf;
		struct bpf_program *block_rq_issue;
		struct bpf_program *block_rq_complete;
	} progs;
	struct {
		struct bpf_link *block_rq_insert_btf;
		struct bpf_link *block_rq_complete_btf;
		struct bpf_link *block_rq_issue;
		struct bpf_link *block_rq_complete;
	} links;

#ifdef __cplusplus
	static inline struct biolatency_bpf *open(const struct bpf_object_open_opts *opts = nullptr);
	static inline struct biolatency_bpf *open_and_load();
	static inline int load(struct biolatency_bpf *skel);
	static inline int attach(struct biolatency_bpf *skel);
	static inline void detach(struct biolatency_bpf *skel);
	static inline void destroy(struct biolatency_bpf *skel);
	static inline const void *elf_bytes(size_t *sz);
#endif /* __cplusplus */
};

static void
biolatency_bpf__destroy(struct biolatency_bpf *obj)
{
	if (!obj)
		return;
	if (obj->skeleton)
		bpf_object__destroy_skeleton(obj->skeleton);
	free(obj);
}

static inline int
biolatency_bpf__create_skeleton(struct biolatency_bpf *obj);

static inline struct biolatency_bpf *
biolatency_bpf__open_opts(const struct bpf_object_open_opts *opts)
{
	struct biolatency_bpf *obj;
	int err;

	obj = (struct biolatency_bpf *)calloc(1, sizeof(*obj));
	if (!obj) {
		errno = ENOMEM;
		return NULL;
	}

	err = biolatency_bpf__create_skeleton(obj);
	if (err)
		goto err_out;

	err = bpf_object__open_skeleton(obj->skeleton, opts);
	if (err)
		goto err_out;

	return obj;
err_out:
	biolatency_bpf__destroy(obj);
	errno = -err;
	return NULL;
}

static inline struct biolatency_bpf *
biolatency_bpf__open(void)
{
	return biolatency_bpf__open_opts(NULL);
}

static inline int
biolatency_bpf__load(struct biolatency_bpf *obj)
{
	return bpf_object__load_skeleton(obj->skeleton);
}

static inline struct biolatency_bpf *
biolatency_bpf__open_and_load(void)
{
	struct biolatency_bpf *obj;
	int err;

	obj = biolatency_bpf__open();
	if (!obj)
		return NULL;
	err = biolatency_bpf__load(obj);
	if (err) {
		biolatency_bpf__destroy(obj);
		errno = -err;
		return NULL;
	}
	return obj;
}

static inline int
biolatency_bpf__attach(struct biolatency_bpf *obj)
{
	return bpf_object__attach_skeleton(obj->skeleton);
}

static inline void
biolatency_bpf__detach(struct biolatency_bpf *obj)
{
	bpf_object__detach_skeleton(obj->skeleton);
}

static inline const void *biolatency_bpf__elf_bytes(size_t *sz);

static inline int
biolatency_bpf__create_skeleton(struct biolatency_bpf *obj)
{
	struct bpf_object_skeleton *s;
	int err;

	s = (struct bpf_object_skeleton *)calloc(1, sizeof(*s));
	if (!s)	{
		err = -ENOMEM;
		goto err;
	}

	s->sz = sizeof(*s);
	s->name = "biolatency_bpf";
	s->obj = &obj->obj;

	/* maps */
	s->map_cnt = 3;
	s->map_skel_sz = sizeof(*s->maps);
	s->maps = (struct bpf_map_skeleton *)calloc(s->map_cnt, s->map_skel_sz);
	if (!s->maps) {
		err = -ENOMEM;
		goto err;
	}

	s->maps[0].name = "start";
	s->maps[0].map = &obj->maps.start;

	s->maps[1].name = "hists";
	s->maps[1].map = &obj->maps.hists;

	s->maps[2].name = "biolaten.bss";
	s->maps[2].map = &obj->maps.bss;

	/* programs */
	s->prog_cnt = 4;
	s->prog_skel_sz = sizeof(*s->progs);
	s->progs = (struct bpf_prog_skeleton *)calloc(s->prog_cnt, s->prog_skel_sz);
	if (!s->progs) {
		err = -ENOMEM;
		goto err;
	}

	s->progs[0].name = "block_rq_insert_btf";
	s->progs[0].prog = &obj->progs.block_rq_insert_btf;
	s->progs[0].link = &obj->links.block_rq_insert_btf;

	s->progs[1].name = "block_rq_complete_btf";
	s->progs[1].prog = &obj->progs.block_rq_complete_btf;
	s->progs[1].link = &obj->links.block_rq_complete_btf;

	s->progs[2].name = "block_rq_issue";
	s->progs[2].prog = &obj->progs.block_rq_issue;
	s->progs[2].link = &obj->links.block_rq_issue;

	s->progs[3].name = "block_rq_complete";
	s->progs[3].prog = &obj->progs.block_rq_complete;
	s->progs[3].link = &obj->links.block_rq_complete;

	s->data = biolatency_bpf__elf_bytes(&s->data_sz);

	obj->skeleton = s;
	return 0;
err:
	bpf_object__destroy_skeleton(s);
	return err;
}

static inline const void *biolatency_bpf__elf_bytes(size_t *sz)
{
	static const char data[] __attribute__((__aligned__(8))) = "\
\x7f\x45\x4c\x46\x02\x01\x01\0\0\0\0\0\0\0\0\0\x01\0\xf7\0\x01\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\xc0\x21\0\0\0\0\0\0\0\0\0\0\x40\0\0\0\0\0\x40\0\x12\0\
\x01\0\0\x2e\x73\x74\x72\x74\x61\x62\0\x2e\x73\x79\x6d\x74\x61\x62\0\x2e\x74\
\x65\x78\x74\0\x74\x70\x5f\x62\x74\x66\x2f\x62\x6c\x6f\x63\x6b\x5f\x72\x71\x5f\
\x69\x6e\x73\x65\x72\x74\0\x74\x70\x5f\x62\x74\x66\x2f\x62\x6c\x6f\x63\x6b\x5f\
\x72\x71\x5f\x63\x6f\x6d\x70\x6c\x65\x74\x65\0\x72\x61\x77\x5f\x74\x70\x2f\x62\
\x6c\x6f\x63\x6b\x5f\x72\x71\x5f\x69\x73\x73\x75\x65\0\x72\x61\x77\x5f\x74\x70\
\x2f\x62\x6c\x6f\x63\x6b\x5f\x72\x71\x5f\x63\x6f\x6d\x70\x6c\x65\x74\x65\0\x6c\
\x69\x63\x65\x6e\x73\x65\0\x2e\x6d\x61\x70\x73\0\x2e\x62\x73\x73\0\x62\x69\x6f\
\x6c\x61\x74\x65\x6e\x63\x79\x2e\x62\x70\x66\x2e\x63\0\x68\x61\x6e\x64\x6c\x65\
\x5f\x62\x6c\x6f\x63\x6b\x5f\x72\x71\x5f\x63\x6f\x6d\x70\x6c\x65\x74\x65\0\x4c\
\x42\x42\x34\x5f\x32\x37\0\x4c\x42\x42\x34\x5f\x32\x36\0\x4c\x42\x42\x34\x5f\
\x34\0\x69\x6e\x69\x74\x69\x61\x6c\x5f\x68\x69\x73\x74\0\x4c\x42\x42\x34\x5f\
\x31\x34\0\x4c\x42\x42\x34\x5f\x37\0\x4c\x42\x42\x34\x5f\x39\0\x4c\x42\x42\x34\
\x5f\x31\x31\0\x4c\x42\x42\x34\x5f\x31\x33\0\x4c\x42\x42\x34\x5f\x32\x33\0\x4c\
\x42\x42\x34\x5f\x31\x36\0\x4c\x42\x42\x34\x5f\x31\x38\0\x4c\x42\x42\x34\x5f\
\x32\x30\0\x4c\x42\x42\x34\x5f\x32\x32\0\x4c\x42\x42\x34\x5f\x32\x35\0\x62\x6c\
\x6f\x63\x6b\x5f\x72\x71\x5f\x69\x6e\x73\x65\x72\x74\x5f\x62\x74\x66\0\x73\x74\
\x61\x72\x74\0\x62\x6c\x6f\x63\x6b\x5f\x72\x71\x5f\x63\x6f\x6d\x70\x6c\x65\x74\
\x65\x5f\x62\x74\x66\0\x62\x6c\x6f\x63\x6b\x5f\x72\x71\x5f\x69\x73\x73\x75\x65\
\0\x62\x6c\x6f\x63\x6b\x5f\x72\x71\x5f\x63\x6f\x6d\x70\x6c\x65\x74\x65\0\x68\
\x69\x73\x74\x73\0\x4c\x49\x43\x45\x4e\x53\x45\0\x2e\x72\x65\x6c\x2e\x74\x65\
\x78\x74\0\x2e\x72\x65\x6c\x74\x70\x5f\x62\x74\x66\x2f\x62\x6c\x6f\x63\x6b\x5f\
\x72\x71\x5f\x69\x6e\x73\x65\x72\x74\0\x2e\x72\x65\x6c\x74\x70\x5f\x62\x74\x66\
\x2f\x62\x6c\x6f\x63\x6b\x5f\x72\x71\x5f\x63\x6f\x6d\x70\x6c\x65\x74\x65\0\x2e\
\x72\x65\x6c\x72\x61\x77\x5f\x74\x70\x2f\x62\x6c\x6f\x63\x6b\x5f\x72\x71\x5f\
\x69\x73\x73\x75\x65\0\x2e\x72\x65\x6c\x72\x61\x77\x5f\x74\x70\x2f\x62\x6c\x6f\
\x63\x6b\x5f\x72\x71\x5f\x63\x6f\x6d\x70\x6c\x65\x74\x65\0\x2e\x42\x54\x46\0\
\x2e\x42\x54\x46\x2e\x65\x78\x74\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\x89\0\0\0\x04\0\xf1\xff\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\x03\0\x03\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x03\0\x04\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\x03\0\x05\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x9a\0\0\
\0\x02\0\x03\0\0\0\0\0\0\0\0\0\x58\x03\0\0\0\0\0\0\0\0\0\0\x03\0\x06\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x03\0\x07\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\xb3\0\0\0\0\0\x03\0\x50\x03\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xbb\0\0\0\0\0\x03\0\
\x28\x03\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xc3\0\0\0\0\0\x03\0\x10\x01\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\xca\0\0\0\x01\0\x0a\0\0\0\0\0\0\0\0\0\x6c\0\0\0\0\0\0\0\xd7\0\0\
\0\0\0\x03\0\x08\x02\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xdf\0\0\0\0\0\x03\0\x50\x01\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\xe6\0\0\0\0\0\x03\0\x78\x01\0\0\0\0\0\0\0\0\0\0\0\0\
\0\0\xed\0\0\0\0\0\x03\0\xa0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xf5\0\0\0\0\0\x03\
\0\xc0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xfd\0\0\0\0\0\x03\0\xe0\x02\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\x05\x01\0\0\0\0\x03\0\x38\x02\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x0d\
\x01\0\0\0\0\x03\0\x60\x02\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x15\x01\0\0\0\0\x03\0\
\x88\x02\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x1d\x01\0\0\0\0\x03\0\xa8\x02\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\x25\x01\0\0\0\0\x03\0\x08\x03\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\0\0\x03\0\x0a\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x2d\x01\0\0\x12\0\x04\0\0\0\0\
\0\0\0\0\0\x70\0\0\0\0\0\0\0\x41\x01\0\0\x11\0\x09\0\0\0\0\0\0\0\0\0\x20\0\0\0\
\0\0\0\0\x47\x01\0\0\x12\0\x05\0\0\0\0\0\0\0\0\0\x20\0\0\0\0\0\0\0\x5d\x01\0\0\
\x12\0\x06\0\0\0\0\0\0\0\0\0\x70\0\0\0\0\0\0\0\x6c\x01\0\0\x12\0\x07\0\0\0\0\0\
\0\0\0\0\x20\0\0\0\0\0\0\0\x7e\x01\0\0\x11\0\x09\0\x20\0\0\0\0\0\0\0\x28\0\0\0\
\0\0\0\0\x84\x01\0\0\x11\0\x08\0\0\0\0\0\0\0\0\0\x04\0\0\0\0\0\0\0\x7b\x1a\xf8\
\xff\0\0\0\0\x85\0\0\0\x05\0\0\0\xbf\x06\0\0\0\0\0\0\xb7\x07\0\0\0\0\0\0\x7b\
\x7a\xf0\xff\0\0\0\0\xbf\xa2\0\0\0\0\0\0\x07\x02\0\0\xf8\xff\xff\xff\x18\x01\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\x85\0\0\0\x01\0\0\0\x15\0\x5f\0\0\0\0\0\x79\x01\0\0\
\0\0\0\0\x1f\x16\0\0\0\0\0\0\x6d\x67\x57\0\0\0\0\0\xbf\xa2\0\0\0\0\0\0\x07\x02\
\0\0\xf0\xff\xff\xff\x18\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x85\0\0\0\x01\0\0\0\
\x55\0\x0e\0\0\0\0\0\xbf\xa7\0\0\0\0\0\0\x07\x07\0\0\xf0\xff\xff\xff\x18\x01\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\xbf\x72\0\0\0\0\0\0\x18\x03\0\0\0\0\0\0\0\0\0\0\0\0\
\0\0\xb7\x04\0\0\0\0\0\0\x85\0\0\0\x02\0\0\0\x18\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\
\0\xbf\x72\0\0\0\0\0\0\x85\0\0\0\x01\0\0\0\x15\0\x43\0\0\0\0\0\x37\x06\0\0\xe8\
\x03\0\0\xbf\x62\0\0\0\0\0\0\x77\x02\0\0\x20\0\0\0\x15\x02\x1b\0\0\0\0\0\xb7\
\x03\0\0\x01\0\0\0\xb7\x01\0\0\x01\0\0\0\x25\x02\x01\0\xff\xff\0\0\xb7\x01\0\0\
\0\0\0\0\x67\x01\0\0\x04\0\0\0\x7f\x12\0\0\0\0\0\0\xb7\x04\0\0\x01\0\0\0\x25\
\x02\x01\0\xff\0\0\0\xb7\x04\0\0\0\0\0\0\x67\x04\0\0\x03\0\0\0\x7f\x42\0\0\0\0\
\0\0\xb7\x05\0\0\x01\0\0\0\x25\x02\x01\0\x0f\0\0\0\xb7\x05\0\0\0\0\0\0\x67\x05\
\0\0\x02\0\0\0\x7f\x52\0\0\0\0\0\0\x25\x02\x01\0\x03\0\0\0\xb7\x03\0\0\0\0\0\0\
\x67\x03\0\0\x01\0\0\0\x7f\x32\0\0\0\0\0\0\x77\x02\0\0\x01\0\0\0\x4f\x21\0\0\0\
\0\0\0\x4f\x41\0\0\0\0\0\0\x4f\x51\0\0\0\0\0\0\x4f\x31\0\0\0\0\0\0\x07\x01\0\0\
\x20\0\0\0\x05\0\x1b\0\0\0\0\0\x67\x06\0\0\x20\0\0\0\x77\x06\0\0\x20\0\0\0\xb7\
\x02\0\0\x01\0\0\0\xb7\x01\0\0\x01\0\0\0\x25\x06\x01\0\xff\xff\0\0\xb7\x01\0\0\
\0\0\0\0\x67\x01\0\0\x04\0\0\0\x7f\x16\0\0\0\0\0\0\xb7\x03\0\0\x01\0\0\0\x25\
\x06\x01\0\xff\0\0\0\xb7\x03\0\0\0\0\0\0\x67\x03\0\0\x03\0\0\0\x7f\x36\0\0\0\0\
\0\0\xb7\x04\0\0\x01\0\0\0\x25\x06\x01\0\x0f\0\0\0\xb7\x04\0\0\0\0\0\0\x67\x04\
\0\0\x02\0\0\0\x7f\x46\0\0\0\0\0\0\x25\x06\x01\0\x03\0\0\0\xb7\x02\0\0\0\0\0\0\
\x67\x02\0\0\x01\0\0\0\x7f\x26\0\0\0\0\0\0\x77\x06\0\0\x01\0\0\0\x4f\x61\0\0\0\
\0\0\0\x4f\x31\0\0\0\0\0\0\x4f\x41\0\0\0\0\0\0\x4f\x21\0\0\0\0\0\0\x67\x01\0\0\
\x20\0\0\0\x77\x01\0\0\x20\0\0\0\xb7\x02\0\0\x1a\0\0\0\x2d\x12\x01\0\0\0\0\0\
\xb7\x01\0\0\x1a\0\0\0\x67\x01\0\0\x02\0\0\0\x0f\x10\0\0\0\0\0\0\xb7\x01\0\0\
\x01\0\0\0\xc3\x10\0\0\0\0\0\0\xbf\xa2\0\0\0\0\0\0\x07\x02\0\0\xf8\xff\xff\xff\
\x18\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x85\0\0\0\x03\0\0\0\x95\0\0\0\0\0\0\0\x79\
\x11\0\0\0\0\0\0\x7b\x1a\xf8\xff\0\0\0\0\x85\0\0\0\x05\0\0\0\x7b\x0a\xf0\xff\0\
\0\0\0\xbf\xa2\0\0\0\0\0\0\x07\x02\0\0\xf8\xff\xff\xff\xbf\xa3\0\0\0\0\0\0\x07\
\x03\0\0\xf0\xff\xff\xff\x18\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xb7\x04\0\0\0\0\0\
\0\x85\0\0\0\x02\0\0\0\xb7\0\0\0\0\0\0\0\x95\0\0\0\0\0\0\0\x79\x11\0\0\0\0\0\0\
\x85\x10\0\0\xff\xff\xff\xff\xb7\0\0\0\0\0\0\0\x95\0\0\0\0\0\0\0\x79\x11\0\0\0\
\0\0\0\x7b\x1a\xf8\xff\0\0\0\0\x85\0\0\0\x05\0\0\0\x7b\x0a\xf0\xff\0\0\0\0\xbf\
\xa2\0\0\0\0\0\0\x07\x02\0\0\xf8\xff\xff\xff\xbf\xa3\0\0\0\0\0\0\x07\x03\0\0\
\xf0\xff\xff\xff\x18\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xb7\x04\0\0\0\0\0\0\x85\0\
\0\0\x02\0\0\0\xb7\0\0\0\0\0\0\0\x95\0\0\0\0\0\0\0\x79\x11\0\0\0\0\0\0\x85\x10\
\0\0\xff\xff\xff\xff\xb7\0\0\0\0\0\0\0\x95\0\0\0\0\0\0\0\x47\x50\x4c\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x38\0\0\0\0\
\0\0\0\x01\0\0\0\x19\0\0\0\x80\0\0\0\0\0\0\0\x01\0\0\0\x1d\0\0\0\xb0\0\0\0\0\0\
\0\0\x01\0\0\0\x1d\0\0\0\xc8\0\0\0\0\0\0\0\x01\0\0\0\x17\0\0\0\xe8\0\0\0\0\0\0\
\0\x01\0\0\0\x1d\0\0\0\x38\x03\0\0\0\0\0\0\x01\0\0\0\x19\0\0\0\x40\0\0\0\0\0\0\
\0\x01\0\0\0\x19\0\0\0\x08\0\0\0\0\0\0\0\x0a\0\0\0\x02\0\0\0\x40\0\0\0\0\0\0\0\
\x01\0\0\0\x19\0\0\0\x08\0\0\0\0\0\0\0\x0a\0\0\0\x02\0\0\0\x9f\xeb\x01\0\x18\0\
\0\0\0\0\0\0\x70\x08\0\0\x70\x08\0\0\0\x0a\0\0\0\0\0\0\0\0\0\x02\x03\0\0\0\x01\
\0\0\0\0\0\0\x01\x04\0\0\0\x20\0\0\x01\0\0\0\0\0\0\0\x03\0\0\0\0\x02\0\0\0\x04\
\0\0\0\x01\0\0\0\x05\0\0\0\0\0\0\x01\x04\0\0\0\x20\0\0\0\0\0\0\0\0\0\0\x02\x06\
\0\0\0\0\0\0\0\0\0\0\x03\0\0\0\0\x02\0\0\0\x04\0\0\0\0\x28\0\0\0\0\0\0\0\0\0\
\x02\x08\0\0\0\0\0\0\0\0\0\0\x02\x09\0\0\0\x19\0\0\0\x22\0\0\x04\x10\x01\0\0\
\x21\0\0\0\x0a\0\0\0\0\0\0\0\x23\0\0\0\x0b\0\0\0\x40\0\0\0\x2a\0\0\0\x0c\0\0\0\
\x80\0\0\0\x32\0\0\0\x0d\0\0\0\xc0\0\0\0\x3c\0\0\0\x10\0\0\0\xe0\0\0\0\x45\0\0\
\0\x02\0\0\0\0\x01\0\0\x49\0\0\0\x02\0\0\0\x20\x01\0\0\x56\0\0\0\x0f\0\0\0\x40\
\x01\0\0\x5e\0\0\0\x0f\0\0\0\x60\x01\0\0\x69\0\0\0\x11\0\0\0\x80\x01\0\0\x72\0\
\0\0\x15\0\0\0\xc0\x01\0\0\x76\0\0\0\x15\0\0\0\0\x02\0\0\0\0\0\0\x16\0\0\0\x40\
\x02\0\0\x7e\0\0\0\x19\0\0\0\xc0\x02\0\0\x83\0\0\0\x12\0\0\0\0\x03\0\0\x91\0\0\
\0\x12\0\0\0\x40\x03\0\0\x9f\0\0\0\x12\0\0\0\x80\x03\0\0\xb0\0\0\0\x1a\0\0\0\
\xc0\x03\0\0\xba\0\0\0\x1a\0\0\0\xd0\x03\0\0\xc8\0\0\0\x1a\0\0\0\xe0\x03\0\0\
\xd9\0\0\0\x1a\0\0\0\xf0\x03\0\0\xef\0\0\0\x1b\0\0\0\0\x04\0\0\xf9\0\0\0\x1c\0\
\0\0\x40\x04\0\0\x07\x01\0\0\x1a\0\0\0\x80\x04\0\0\x0e\x01\0\0\x1d\0\0\0\xa0\
\x04\0\0\x14\x01\0\0\x1e\0\0\0\xc0\x04\0\0\x18\x01\0\0\x20\0\0\0\0\x05\0\0\0\0\
\0\0\x21\0\0\0\x40\x05\0\0\0\0\0\0\x27\0\0\0\xc0\x05\0\0\x21\x01\0\0\x2c\0\0\0\
\x80\x06\0\0\x25\x01\0\0\x30\0\0\0\x40\x07\0\0\x2b\x01\0\0\x12\0\0\0\xc0\x07\0\
\0\x35\x01\0\0\x31\0\0\0\0\x08\0\0\x3c\x01\0\0\x2e\0\0\0\x40\x08\0\0\0\0\0\0\0\
\0\0\x02\x50\0\0\0\0\0\0\0\0\0\0\x02\x57\0\0\0\0\0\0\0\0\0\0\x02\x56\0\0\0\x48\
\x01\0\0\0\0\0\x08\x0e\0\0\0\x52\x01\0\0\0\0\0\x08\x0f\0\0\0\x58\x01\0\0\0\0\0\
\x01\x04\0\0\0\x20\0\0\0\x65\x01\0\0\0\0\0\x08\x0e\0\0\0\x71\x01\0\0\0\0\0\x08\
\x12\0\0\0\x7a\x01\0\0\0\0\0\x08\x13\0\0\0\x7e\x01\0\0\0\0\0\x08\x14\0\0\0\x84\
\x01\0\0\0\0\0\x01\x08\0\0\0\x40\0\0\0\0\0\0\0\0\0\0\x02\x52\0\0\0\0\0\0\0\x02\
\0\0\x05\x10\0\0\0\x97\x01\0\0\x17\0\0\0\0\0\0\0\xa1\x01\0\0\x08\0\0\0\0\0\0\0\
\xa9\x01\0\0\x02\0\0\x04\x10\0\0\0\xb3\x01\0\0\x18\0\0\0\0\0\0\0\xb8\x01\0\0\
\x18\0\0\0\x40\0\0\0\0\0\0\0\0\0\0\x02\x17\0\0\0\0\0\0\0\0\0\0\x02\x53\0\0\0\
\xbd\x01\0\0\0\0\0\x01\x02\0\0\0\x10\0\0\0\0\0\0\0\0\0\0\x02\x54\0\0\0\0\0\0\0\
\0\0\0\x02\x58\0\0\0\xcc\x01\0\0\x03\0\0\x06\x04\0\0\0\xd8\x01\0\0\0\0\0\0\xe3\
\x01\0\0\x01\0\0\0\xf3\x01\0\0\x02\0\0\0\x02\x02\0\0\0\0\0\x08\x1f\0\0\0\0\0\0\
\0\x01\0\0\x04\x04\0\0\0\x0b\x02\0\0\x02\0\0\0\0\0\0\0\x13\x02\0\0\0\0\0\x01\
\x08\0\0\0\x40\0\0\0\0\0\0\0\x02\0\0\x05\x10\0\0\0\x21\x02\0\0\x22\0\0\0\0\0\0\
\0\x26\x02\0\0\x25\0\0\0\0\0\0\0\x2f\x02\0\0\x02\0\0\x04\x10\0\0\0\xb3\x01\0\0\
\x23\0\0\0\0\0\0\0\x3a\x02\0\0\x24\0\0\0\x40\0\0\0\0\0\0\0\0\0\0\x02\x22\0\0\0\
\0\0\0\0\0\0\0\x02\x23\0\0\0\x40\x02\0\0\x01\0\0\x04\x08\0\0\0\xb3\x01\0\0\x26\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x02\x25\0\0\0\0\0\0\0\x02\0\0\x05\x18\0\0\0\x4b\
\x02\0\0\x28\0\0\0\0\0\0\0\x53\x02\0\0\x2a\0\0\0\0\0\0\0\x4b\x02\0\0\x03\0\0\
\x04\x18\0\0\0\x5f\x02\0\0\x20\0\0\0\0\0\0\0\x71\x02\0\0\x29\0\0\0\x40\0\0\0\
\x7a\x02\0\0\x29\0\0\0\x80\0\0\0\0\0\0\0\0\0\0\x02\x28\0\0\0\x82\x02\0\0\x03\0\
\0\x04\x10\0\0\0\x8a\x02\0\0\x2b\0\0\0\0\0\0\0\x92\x02\0\0\x0f\0\0\0\x40\0\0\0\
\x99\x02\0\0\x0f\0\0\0\x60\0\0\0\0\0\0\0\0\0\0\x02\x51\0\0\0\0\0\0\0\x02\0\0\
\x04\x18\0\0\0\xa3\x02\0\0\x2d\0\0\0\0\0\0\0\xa7\x02\0\0\x2f\0\0\0\x40\0\0\0\0\
\0\0\0\0\0\0\x02\x55\0\0\0\0\0\0\0\0\0\0\x02\0\0\0\0\0\0\0\0\0\0\0\x03\0\0\0\0\
\x2e\0\0\0\x04\0\0\0\x02\0\0\0\0\0\0\0\x02\0\0\x04\x10\0\0\0\xac\x02\0\0\x0f\0\
\0\0\0\0\0\0\xb0\x02\0\0\x31\0\0\0\x40\0\0\0\0\0\0\0\0\0\0\x02\x32\0\0\0\xbd\
\x02\0\0\0\0\0\x08\x33\0\0\0\0\0\0\0\x02\0\0\x0d\x34\0\0\0\0\0\0\0\x08\0\0\0\0\
\0\0\0\x35\0\0\0\xca\x02\0\0\x02\0\0\x06\x04\0\0\0\xd8\x02\0\0\0\0\0\0\xe7\x02\
\0\0\x01\0\0\0\xf6\x02\0\0\0\0\0\x08\x36\0\0\0\x03\x03\0\0\0\0\0\x08\x37\0\0\0\
\x06\x03\0\0\0\0\0\x08\x38\0\0\0\x0b\x03\0\0\0\0\0\x01\x01\0\0\0\x08\0\0\0\0\0\
\0\0\0\0\0\x02\x12\0\0\0\0\0\0\0\x04\0\0\x04\x20\0\0\0\x19\x03\0\0\x01\0\0\0\0\
\0\0\0\x1e\x03\0\0\x05\0\0\0\x40\0\0\0\x2a\x03\0\0\x07\0\0\0\x80\0\0\0\x2e\x03\
\0\0\x39\0\0\0\xc0\0\0\0\x34\x03\0\0\0\0\0\x0e\x3a\0\0\0\x01\0\0\0\0\0\0\0\0\0\
\0\x02\x3d\0\0\0\x3a\x03\0\0\x02\0\0\x04\x08\0\0\0\x32\0\0\0\x0e\0\0\0\0\0\0\0\
\x43\x03\0\0\x0e\0\0\0\x20\0\0\0\0\0\0\0\0\0\0\x02\x3f\0\0\0\x47\x03\0\0\x01\0\
\0\x04\x6c\0\0\0\x4c\x03\0\0\x40\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x03\0\0\0\0\x0e\0\
\0\0\x04\0\0\0\x1b\0\0\0\0\0\0\0\x05\0\0\x04\x28\0\0\0\x19\x03\0\0\x01\0\0\0\0\
\0\0\0\x1e\x03\0\0\x05\0\0\0\x40\0\0\0\x2a\x03\0\0\x3c\0\0\0\x80\0\0\0\x2e\x03\
\0\0\x3e\0\0\0\xc0\0\0\0\x52\x03\0\0\x01\0\0\0\0\x01\0\0\x5a\x03\0\0\0\0\0\x0e\
\x41\0\0\0\x01\0\0\0\0\0\0\0\x01\0\0\x0d\x02\0\0\0\x60\x03\0\0\x39\0\0\0\x64\
\x03\0\0\x01\0\0\x0c\x43\0\0\0\0\0\0\0\0\0\0\x02\x14\0\0\0\0\0\0\0\x01\0\0\x0d\
\x02\0\0\0\x60\x03\0\0\x45\0\0\0\x78\x03\0\0\x01\0\0\x0c\x46\0\0\0\x8e\x03\0\0\
\x01\0\0\x0c\x46\0\0\0\x9d\x03\0\0\x01\0\0\x0c\x46\0\0\0\0\0\0\0\x03\0\0\x0d\
\x02\0\0\0\xaf\x03\0\0\x08\0\0\0\xb2\x03\0\0\x02\0\0\0\xb8\x03\0\0\x0f\0\0\0\
\xc1\x03\0\0\0\0\0\x0c\x4a\0\0\0\xda\x03\0\0\0\0\0\x01\x01\0\0\0\x08\0\0\x01\0\
\0\0\0\0\0\0\x03\0\0\0\0\x4c\0\0\0\x04\0\0\0\x04\0\0\0\xdf\x03\0\0\0\0\0\x0e\
\x4d\0\0\0\x01\0\0\0\xe7\x03\0\0\0\0\0\x0e\x3f\0\0\0\0\0\0\0\xf4\x03\0\0\0\0\0\
\x07\0\0\0\0\x02\x04\0\0\0\0\0\x07\0\0\0\0\x72\0\0\0\0\0\0\x07\0\0\0\0\x07\x04\
\0\0\0\0\0\x07\0\0\0\0\x14\x04\0\0\0\0\0\x07\0\0\0\0\x22\x04\0\0\0\0\0\x07\0\0\
\0\0\x28\x04\0\0\0\0\0\x07\0\0\0\0\x36\x04\0\0\0\0\0\x07\0\0\0\0\x41\x04\0\0\0\
\0\0\x07\0\0\0\0\x88\x09\0\0\x01\0\0\x0f\x04\0\0\0\x4e\0\0\0\0\0\0\0\x04\0\0\0\
\x90\x09\0\0\x02\0\0\x0f\x48\0\0\0\x3b\0\0\0\0\0\0\0\x20\0\0\0\x42\0\0\0\x20\0\
\0\0\x28\0\0\0\x96\x09\0\0\x01\0\0\x0f\x6c\0\0\0\x4f\0\0\0\0\0\0\0\x6c\0\0\0\0\
\x69\x6e\x74\0\x5f\x5f\x41\x52\x52\x41\x59\x5f\x53\x49\x5a\x45\x5f\x54\x59\x50\
\x45\x5f\x5f\0\x72\x65\x71\x75\x65\x73\x74\0\x71\0\x6d\x71\x5f\x63\x74\x78\0\
\x6d\x71\x5f\x68\x63\x74\x78\0\x63\x6d\x64\x5f\x66\x6c\x61\x67\x73\0\x72\x71\
\x5f\x66\x6c\x61\x67\x73\0\x74\x61\x67\0\x69\x6e\x74\x65\x72\x6e\x61\x6c\x5f\
\x74\x61\x67\0\x74\x69\x6d\x65\x6f\x75\x74\0\x5f\x5f\x64\x61\x74\x61\x5f\x6c\
\x65\x6e\0\x5f\x5f\x73\x65\x63\x74\x6f\x72\0\x62\x69\x6f\0\x62\x69\x6f\x74\x61\
\x69\x6c\0\x70\x61\x72\x74\0\x61\x6c\x6c\x6f\x63\x5f\x74\x69\x6d\x65\x5f\x6e\
\x73\0\x73\x74\x61\x72\x74\x5f\x74\x69\x6d\x65\x5f\x6e\x73\0\x69\x6f\x5f\x73\
\x74\x61\x72\x74\x5f\x74\x69\x6d\x65\x5f\x6e\x73\0\x77\x62\x74\x5f\x66\x6c\x61\
\x67\x73\0\x73\x74\x61\x74\x73\x5f\x73\x65\x63\x74\x6f\x72\x73\0\x6e\x72\x5f\
\x70\x68\x79\x73\x5f\x73\x65\x67\x6d\x65\x6e\x74\x73\0\x6e\x72\x5f\x69\x6e\x74\
\x65\x67\x72\x69\x74\x79\x5f\x73\x65\x67\x6d\x65\x6e\x74\x73\0\x63\x72\x79\x70\
\x74\x5f\x63\x74\x78\0\x63\x72\x79\x70\x74\x5f\x6b\x65\x79\x73\x6c\x6f\x74\0\
\x69\x6f\x70\x72\x69\x6f\0\x73\x74\x61\x74\x65\0\x72\x65\x66\0\x64\x65\x61\x64\
\x6c\x69\x6e\x65\0\x65\x6c\x76\0\x66\x6c\x75\x73\x68\0\x66\x69\x66\x6f\x5f\x74\
\x69\x6d\x65\0\x65\x6e\x64\x5f\x69\x6f\0\x65\x6e\x64\x5f\x69\x6f\x5f\x64\x61\
\x74\x61\0\x62\x6c\x6b\x5f\x6f\x70\x66\x5f\x74\0\x5f\x5f\x75\x33\x32\0\x75\x6e\
\x73\x69\x67\x6e\x65\x64\x20\x69\x6e\x74\0\x72\x65\x71\x5f\x66\x6c\x61\x67\x73\
\x5f\x74\0\x73\x65\x63\x74\x6f\x72\x5f\x74\0\x75\x36\x34\0\x5f\x5f\x75\x36\x34\
\0\x75\x6e\x73\x69\x67\x6e\x65\x64\x20\x6c\x6f\x6e\x67\x20\x6c\x6f\x6e\x67\0\
\x71\x75\x65\x75\x65\x6c\x69\x73\x74\0\x72\x71\x5f\x6e\x65\x78\x74\0\x6c\x69\
\x73\x74\x5f\x68\x65\x61\x64\0\x6e\x65\x78\x74\0\x70\x72\x65\x76\0\x75\x6e\x73\
\x69\x67\x6e\x65\x64\x20\x73\x68\x6f\x72\x74\0\x6d\x71\x5f\x72\x71\x5f\x73\x74\
\x61\x74\x65\0\x4d\x51\x5f\x52\x51\x5f\x49\x44\x4c\x45\0\x4d\x51\x5f\x52\x51\
\x5f\x49\x4e\x5f\x46\x4c\x49\x47\x48\x54\0\x4d\x51\x5f\x52\x51\x5f\x43\x4f\x4d\
\x50\x4c\x45\x54\x45\0\x61\x74\x6f\x6d\x69\x63\x5f\x74\0\x63\x6f\x75\x6e\x74\
\x65\x72\0\x75\x6e\x73\x69\x67\x6e\x65\x64\x20\x6c\x6f\x6e\x67\0\x68\x61\x73\
\x68\0\x69\x70\x69\x5f\x6c\x69\x73\x74\0\x68\x6c\x69\x73\x74\x5f\x6e\x6f\x64\
\x65\0\x70\x70\x72\x65\x76\0\x6c\x6c\x69\x73\x74\x5f\x6e\x6f\x64\x65\0\x72\x62\
\x5f\x6e\x6f\x64\x65\0\x73\x70\x65\x63\x69\x61\x6c\x5f\x76\x65\x63\0\x5f\x5f\
\x72\x62\x5f\x70\x61\x72\x65\x6e\x74\x5f\x63\x6f\x6c\x6f\x72\0\x72\x62\x5f\x72\
\x69\x67\x68\x74\0\x72\x62\x5f\x6c\x65\x66\x74\0\x62\x69\x6f\x5f\x76\x65\x63\0\
\x62\x76\x5f\x70\x61\x67\x65\0\x62\x76\x5f\x6c\x65\x6e\0\x62\x76\x5f\x6f\x66\
\x66\x73\x65\x74\0\x69\x63\x71\0\x70\x72\x69\x76\0\x73\x65\x71\0\x73\x61\x76\
\x65\x64\x5f\x65\x6e\x64\x5f\x69\x6f\0\x72\x71\x5f\x65\x6e\x64\x5f\x69\x6f\x5f\
\x66\x6e\0\x72\x71\x5f\x65\x6e\x64\x5f\x69\x6f\x5f\x72\x65\x74\0\x52\x51\x5f\
\x45\x4e\x44\x5f\x49\x4f\x5f\x4e\x4f\x4e\x45\0\x52\x51\x5f\x45\x4e\x44\x5f\x49\
\x4f\x5f\x46\x52\x45\x45\0\x62\x6c\x6b\x5f\x73\x74\x61\x74\x75\x73\x5f\x74\0\
\x75\x38\0\x5f\x5f\x75\x38\0\x75\x6e\x73\x69\x67\x6e\x65\x64\x20\x63\x68\x61\
\x72\0\x74\x79\x70\x65\0\x6d\x61\x78\x5f\x65\x6e\x74\x72\x69\x65\x73\0\x6b\x65\
\x79\0\x76\x61\x6c\x75\x65\0\x73\x74\x61\x72\x74\0\x68\x69\x73\x74\x5f\x6b\x65\
\x79\0\x64\x65\x76\0\x68\x69\x73\x74\0\x73\x6c\x6f\x74\x73\0\x70\x69\x6e\x6e\
\x69\x6e\x67\0\x68\x69\x73\x74\x73\0\x63\x74\x78\0\x62\x6c\x6f\x63\x6b\x5f\x72\
\x71\x5f\x69\x6e\x73\x65\x72\x74\x5f\x62\x74\x66\0\x62\x6c\x6f\x63\x6b\x5f\x72\
\x71\x5f\x63\x6f\x6d\x70\x6c\x65\x74\x65\x5f\x62\x74\x66\0\x62\x6c\x6f\x63\x6b\
\x5f\x72\x71\x5f\x69\x73\x73\x75\x65\0\x62\x6c\x6f\x63\x6b\x5f\x72\x71\x5f\x63\
\x6f\x6d\x70\x6c\x65\x74\x65\0\x72\x71\0\x65\x72\x72\x6f\x72\0\x6e\x72\x5f\x62\
\x79\x74\x65\x73\0\x68\x61\x6e\x64\x6c\x65\x5f\x62\x6c\x6f\x63\x6b\x5f\x72\x71\
\x5f\x63\x6f\x6d\x70\x6c\x65\x74\x65\0\x63\x68\x61\x72\0\x4c\x49\x43\x45\x4e\
\x53\x45\0\x69\x6e\x69\x74\x69\x61\x6c\x5f\x68\x69\x73\x74\0\x72\x65\x71\x75\
\x65\x73\x74\x5f\x71\x75\x65\x75\x65\0\x70\x61\x67\x65\0\x62\x6c\x6f\x63\x6b\
\x5f\x64\x65\x76\x69\x63\x65\0\x62\x69\x6f\x5f\x63\x72\x79\x70\x74\x5f\x63\x74\
\x78\0\x69\x6f\x5f\x63\x71\0\x62\x6c\x6b\x5f\x6d\x71\x5f\x68\x77\x5f\x63\x74\
\x78\0\x62\x6c\x6b\x5f\x6d\x71\x5f\x63\x74\x78\0\x62\x6c\x6b\x5f\x63\x72\x79\
\x70\x74\x6f\x5f\x6b\x65\x79\x73\x6c\x6f\x74\0\x2f\x68\x6f\x6d\x65\x2f\x6f\x73\
\x75\x73\x65\x2f\x65\x62\x70\x66\x2d\x6e\x65\x72\x73\x63\x2f\x6d\x69\x6e\x69\
\x6d\x61\x6c\x2d\x6c\x69\x62\x62\x70\x66\x2f\x62\x69\x6f\x6c\x61\x74\x65\x6e\
\x63\x79\x2e\x62\x70\x66\x2e\x63\0\x09\x72\x65\x74\x75\x72\x6e\x20\x74\x72\x61\
\x63\x65\x5f\x72\x71\x5f\x73\x74\x61\x72\x74\x28\x28\x76\x6f\x69\x64\x20\x2a\
\x29\x63\x74\x78\x5b\x30\x5d\x2c\x20\x66\x61\x6c\x73\x65\x29\x3b\0\x09\x74\x73\
\x20\x3d\x20\x62\x70\x66\x5f\x6b\x74\x69\x6d\x65\x5f\x67\x65\x74\x5f\x6e\x73\
\x28\x29\x3b\0\x09\x62\x70\x66\x5f\x6d\x61\x70\x5f\x75\x70\x64\x61\x74\x65\x5f\
\x65\x6c\x65\x6d\x28\x26\x73\x74\x61\x72\x74\x2c\x20\x26\x72\x71\x2c\x20\x26\
\x74\x73\x2c\x20\x30\x29\x3b\0\x09\x72\x65\x74\x75\x72\x6e\x20\x68\x61\x6e\x64\
\x6c\x65\x5f\x62\x6c\x6f\x63\x6b\x5f\x72\x71\x5f\x69\x6e\x73\x65\x72\x74\x28\
\x63\x74\x78\x29\x3b\0\x69\x6e\x74\x20\x42\x50\x46\x5f\x50\x52\x4f\x47\x28\x62\
\x6c\x6f\x63\x6b\x5f\x72\x71\x5f\x63\x6f\x6d\x70\x6c\x65\x74\x65\x5f\x62\x74\
\x66\x2c\x20\x73\x74\x72\x75\x63\x74\x20\x72\x65\x71\x75\x65\x73\x74\x20\x2a\
\x72\x71\x2c\x20\x69\x6e\x74\x20\x65\x72\x72\x6f\x72\x2c\x20\x75\x6e\x73\x69\
\x67\x6e\x65\x64\x20\x69\x6e\x74\x20\x6e\x72\x5f\x62\x79\x74\x65\x73\x29\0\x09\
\x72\x65\x74\x75\x72\x6e\x20\x68\x61\x6e\x64\x6c\x65\x5f\x62\x6c\x6f\x63\x6b\
\x5f\x72\x71\x5f\x63\x6f\x6d\x70\x6c\x65\x74\x65\x28\x72\x71\x2c\x20\x65\x72\
\x72\x6f\x72\x2c\x20\x6e\x72\x5f\x62\x79\x74\x65\x73\x29\x3b\0\x09\x72\x65\x74\
\x75\x72\x6e\x20\x74\x72\x61\x63\x65\x5f\x72\x71\x5f\x73\x74\x61\x72\x74\x28\
\x28\x76\x6f\x69\x64\x20\x2a\x29\x63\x74\x78\x5b\x30\x5d\x2c\x20\x74\x72\x75\
\x65\x29\x3b\0\x69\x6e\x74\x20\x42\x50\x46\x5f\x50\x52\x4f\x47\x28\x62\x6c\x6f\
\x63\x6b\x5f\x72\x71\x5f\x69\x73\x73\x75\x65\x29\0\x69\x6e\x74\x20\x42\x50\x46\
\x5f\x50\x52\x4f\x47\x28\x62\x6c\x6f\x63\x6b\x5f\x72\x71\x5f\x63\x6f\x6d\x70\
\x6c\x65\x74\x65\x2c\x20\x73\x74\x72\x75\x63\x74\x20\x72\x65\x71\x75\x65\x73\
\x74\x20\x2a\x72\x71\x2c\x20\x69\x6e\x74\x20\x65\x72\x72\x6f\x72\x2c\x20\x75\
\x6e\x73\x69\x67\x6e\x65\x64\x20\x69\x6e\x74\x20\x6e\x72\x5f\x62\x79\x74\x65\
\x73\x29\0\x73\x74\x61\x74\x69\x63\x20\x69\x6e\x74\x20\x68\x61\x6e\x64\x6c\x65\
\x5f\x62\x6c\x6f\x63\x6b\x5f\x72\x71\x5f\x63\x6f\x6d\x70\x6c\x65\x74\x65\x28\
\x73\x74\x72\x75\x63\x74\x20\x72\x65\x71\x75\x65\x73\x74\x20\x2a\x72\x71\x2c\
\x20\x69\x6e\x74\x20\x65\x72\x72\x6f\x72\x2c\x20\x75\x6e\x73\x69\x67\x6e\x65\
\x64\x20\x69\x6e\x74\x20\x6e\x72\x5f\x62\x79\x74\x65\x73\x29\0\x09\x75\x36\x34\
\x20\x73\x6c\x6f\x74\x2c\x20\x2a\x74\x73\x70\x2c\x20\x74\x73\x20\x3d\x20\x62\
\x70\x66\x5f\x6b\x74\x69\x6d\x65\x5f\x67\x65\x74\x5f\x6e\x73\x28\x29\x3b\0\x09\
\x73\x74\x72\x75\x63\x74\x20\x68\x69\x73\x74\x5f\x6b\x65\x79\x20\x68\x6b\x65\
\x79\x20\x3d\x20\x7b\x7d\x3b\0\x09\x74\x73\x70\x20\x3d\x20\x62\x70\x66\x5f\x6d\
\x61\x70\x5f\x6c\x6f\x6f\x6b\x75\x70\x5f\x65\x6c\x65\x6d\x28\x26\x73\x74\x61\
\x72\x74\x2c\x20\x26\x72\x71\x29\x3b\0\x09\x69\x66\x20\x28\x21\x74\x73\x70\x29\
\0\x09\x64\x65\x6c\x74\x61\x20\x3d\x20\x28\x73\x36\x34\x29\x28\x74\x73\x20\x2d\
\x20\x2a\x74\x73\x70\x29\x3b\0\x09\x69\x66\x20\x28\x64\x65\x6c\x74\x61\x20\x3c\
\x20\x30\x29\0\x09\x68\x69\x73\x74\x70\x20\x3d\x20\x62\x70\x66\x5f\x6d\x61\x70\
\x5f\x6c\x6f\x6f\x6b\x75\x70\x5f\x65\x6c\x65\x6d\x28\x26\x68\x69\x73\x74\x73\
\x2c\x20\x26\x68\x6b\x65\x79\x29\x3b\0\x09\x69\x66\x20\x28\x21\x68\x69\x73\x74\
\x70\x29\x20\x7b\0\x09\x09\x62\x70\x66\x5f\x6d\x61\x70\x5f\x75\x70\x64\x61\x74\
\x65\x5f\x65\x6c\x65\x6d\x28\x26\x68\x69\x73\x74\x73\x2c\x20\x26\x68\x6b\x65\
\x79\x2c\x20\x26\x69\x6e\x69\x74\x69\x61\x6c\x5f\x68\x69\x73\x74\x2c\x20\x30\
\x29\x3b\0\x09\x09\x68\x69\x73\x74\x70\x20\x3d\x20\x62\x70\x66\x5f\x6d\x61\x70\
\x5f\x6c\x6f\x6f\x6b\x75\x70\x5f\x65\x6c\x65\x6d\x28\x26\x68\x69\x73\x74\x73\
\x2c\x20\x26\x68\x6b\x65\x79\x29\x3b\0\x09\x09\x69\x66\x20\x28\x21\x68\x69\x73\
\x74\x70\x29\0\x09\x75\x33\x32\x20\x68\x69\x20\x3d\x20\x76\x20\x3e\x3e\x20\x33\
\x32\x3b\0\x09\x69\x66\x20\x28\x68\x69\x29\0\x09\x72\x20\x3d\x20\x28\x76\x20\
\x3e\x20\x30\x78\x46\x46\x46\x46\x29\x20\x3c\x3c\x20\x34\x3b\x20\x76\x20\x3e\
\x3e\x3d\x20\x72\x3b\0\x09\x73\x68\x69\x66\x74\x20\x3d\x20\x28\x76\x20\x3e\x20\
\x30\x78\x46\x46\x29\x20\x3c\x3c\x20\x33\x3b\x20\x76\x20\x3e\x3e\x3d\x20\x73\
\x68\x69\x66\x74\x3b\x20\x72\x20\x7c\x3d\x20\x73\x68\x69\x66\x74\x3b\0\x09\x73\
\x68\x69\x66\x74\x20\x3d\x20\x28\x76\x20\x3e\x20\x30\x78\x46\x29\x20\x3c\x3c\
\x20\x32\x3b\x20\x76\x20\x3e\x3e\x3d\x20\x73\x68\x69\x66\x74\x3b\x20\x72\x20\
\x7c\x3d\x20\x73\x68\x69\x66\x74\x3b\0\x09\x73\x68\x69\x66\x74\x20\x3d\x20\x28\
\x76\x20\x3e\x20\x30\x78\x33\x29\x20\x3c\x3c\x20\x31\x3b\x20\x76\x20\x3e\x3e\
\x3d\x20\x73\x68\x69\x66\x74\x3b\x20\x72\x20\x7c\x3d\x20\x73\x68\x69\x66\x74\
\x3b\0\x09\x72\x20\x7c\x3d\x20\x28\x76\x20\x3e\x3e\x20\x31\x29\x3b\0\x09\x09\
\x72\x65\x74\x75\x72\x6e\x20\x6c\x6f\x67\x32\x28\x68\x69\x29\x20\x2b\x20\x33\
\x32\x3b\0\x09\x09\x72\x65\x74\x75\x72\x6e\x20\x6c\x6f\x67\x32\x28\x76\x29\x3b\
\0\x09\x69\x66\x20\x28\x73\x6c\x6f\x74\x20\x3e\x3d\x20\x4d\x41\x58\x5f\x53\x4c\
\x4f\x54\x53\x29\0\x09\x5f\x5f\x73\x79\x6e\x63\x5f\x66\x65\x74\x63\x68\x5f\x61\
\x6e\x64\x5f\x61\x64\x64\x28\x26\x68\x69\x73\x74\x70\x2d\x3e\x73\x6c\x6f\x74\
\x73\x5b\x73\x6c\x6f\x74\x5d\x2c\x20\x31\x29\x3b\0\x63\x6c\x65\x61\x6e\x75\x70\
\x3a\0\x09\x62\x70\x66\x5f\x6d\x61\x70\x5f\x64\x65\x6c\x65\x74\x65\x5f\x65\x6c\
\x65\x6d\x28\x26\x73\x74\x61\x72\x74\x2c\x20\x26\x72\x71\x29\x3b\0\x7d\0\x6c\
\x69\x63\x65\x6e\x73\x65\0\x2e\x6d\x61\x70\x73\0\x2e\x62\x73\x73\0\x2e\x74\x65\
\x78\x74\0\x74\x70\x5f\x62\x74\x66\x2f\x62\x6c\x6f\x63\x6b\x5f\x72\x71\x5f\x69\
\x6e\x73\x65\x72\x74\0\x74\x70\x5f\x62\x74\x66\x2f\x62\x6c\x6f\x63\x6b\x5f\x72\
\x71\x5f\x63\x6f\x6d\x70\x6c\x65\x74\x65\0\x72\x61\x77\x5f\x74\x70\x2f\x62\x6c\
\x6f\x63\x6b\x5f\x72\x71\x5f\x69\x73\x73\x75\x65\0\x72\x61\x77\x5f\x74\x70\x2f\
\x62\x6c\x6f\x63\x6b\x5f\x72\x71\x5f\x63\x6f\x6d\x70\x6c\x65\x74\x65\0\x9f\xeb\
\x01\0\x20\0\0\0\0\0\0\0\x54\0\0\0\x54\0\0\0\x1c\x04\0\0\x70\x04\0\0\0\0\0\0\
\x08\0\0\0\x9b\x09\0\0\x01\0\0\0\0\0\0\0\x4b\0\0\0\xa1\x09\0\0\x01\0\0\0\0\0\0\
\0\x44\0\0\0\xb8\x09\0\0\x01\0\0\0\0\0\0\0\x47\0\0\0\xd1\x09\0\0\x01\0\0\0\0\0\
\0\0\x48\0\0\0\xe7\x09\0\0\x01\0\0\0\0\0\0\0\x49\0\0\0\x10\0\0\0\x9b\x09\0\0\
\x2d\0\0\0\0\0\0\0\x54\x04\0\0\x56\x06\0\0\0\x44\x01\0\x08\0\0\0\x54\x04\0\0\
\xb0\x06\0\0\x17\x4c\x01\0\x20\0\0\0\x54\x04\0\0\xda\x06\0\0\x12\x50\x01\0\x30\
\0\0\0\x54\x04\0\0\xb0\x06\0\0\x17\x4c\x01\0\x38\0\0\0\x54\x04\0\0\xf6\x06\0\0\
\x08\x60\x01\0\x50\0\0\0\x54\x04\0\0\x1f\x07\0\0\x06\x64\x01\0\x58\0\0\0\x54\
\x04\0\0\x2a\x07\0\0\x15\x70\x01\0\x60\0\0\0\x54\x04\0\0\x2a\x07\0\0\x13\x70\
\x01\0\x68\0\0\0\x54\x04\0\0\x45\x07\0\0\x06\x74\x01\0\x78\0\0\0\x54\x04\0\0\
\x55\x07\0\0\x0a\x80\x01\0\x98\0\0\0\x54\x04\0\0\x82\x07\0\0\x06\x84\x01\0\xa8\
\0\0\0\x54\x04\0\0\x91\x07\0\0\x03\x88\x01\0\xe8\0\0\0\x54\x04\0\0\xc9\x07\0\0\
\x0b\x8c\x01\0\x08\x01\0\0\x54\x04\0\0\xf7\x07\0\0\x07\x90\x01\0\x18\x01\0\0\
\x54\x04\0\0\x05\x08\0\0\x0d\xac\0\0\x28\x01\0\0\x54\x04\0\0\x18\x08\0\0\x06\
\xb4\0\0\x40\x01\0\0\x54\x04\0\0\x05\x08\0\0\x0b\xac\0\0\x50\x01\0\0\x54\x04\0\
\0\x21\x08\0\0\x13\x80\0\0\x58\x01\0\0\x54\x04\0\0\x21\x08\0\0\x1b\x80\0\0\x78\
\x01\0\0\x54\x04\0\0\x42\x08\0\0\x15\x84\0\0\x80\x01\0\0\x54\x04\0\0\x42\x08\0\
\0\x1d\x84\0\0\xa0\x01\0\0\x54\x04\0\0\x75\x08\0\0\x14\x88\0\0\xa8\x01\0\0\x54\
\x04\0\0\x75\x08\0\0\x1c\x88\0\0\xc0\x01\0\0\x54\x04\0\0\xa7\x08\0\0\x14\x8c\0\
\0\xc8\x01\0\0\x54\x04\0\0\xa7\x08\0\0\x1c\x8c\0\0\xd0\x01\0\0\x54\x04\0\0\xd9\
\x08\0\0\x0a\x90\0\0\xd8\x01\0\0\x54\x04\0\0\xd9\x08\0\0\x04\x90\0\0\xf8\x01\0\
\0\x54\x04\0\0\xe9\x08\0\0\x13\xb8\0\0\x08\x02\0\0\x54\x04\0\0\x01\x09\0\0\x0f\
\xc0\0\0\x38\x02\0\0\x54\x04\0\0\x21\x08\0\0\x13\x80\0\0\x40\x02\0\0\x54\x04\0\
\0\x21\x08\0\0\x1b\x80\0\0\x60\x02\0\0\x54\x04\0\0\x42\x08\0\0\x15\x84\0\0\x68\
\x02\0\0\x54\x04\0\0\x42\x08\0\0\x1d\x84\0\0\x88\x02\0\0\x54\x04\0\0\x75\x08\0\
\0\x14\x88\0\0\x90\x02\0\0\x54\x04\0\0\x75\x08\0\0\x1c\x88\0\0\xa8\x02\0\0\x54\
\x04\0\0\xa7\x08\0\0\x14\x8c\0\0\xb0\x02\0\0\x54\x04\0\0\xa7\x08\0\0\x1c\x8c\0\
\0\xb8\x02\0\0\x54\x04\0\0\xd9\x08\0\0\x0a\x90\0\0\xc0\x02\0\0\x54\x04\0\0\xd9\
\x08\0\0\x04\x90\0\0\xe0\x02\0\0\x54\x04\0\0\x13\x09\0\0\x06\xa8\x01\0\x08\x03\
\0\0\x54\x04\0\0\x2b\x09\0\0\x18\xb0\x01\0\x20\x03\0\0\x54\x04\0\0\x2b\x09\0\0\
\x02\xb0\x01\0\x30\x03\0\0\x54\x04\0\0\x5a\x09\0\0\x01\xb8\x01\0\x38\x03\0\0\
\x54\x04\0\0\x63\x09\0\0\x02\xbc\x01\0\x50\x03\0\0\x54\x04\0\0\x86\x09\0\0\x01\
\xc4\x01\0\xa1\x09\0\0\x06\0\0\0\0\0\0\0\x54\x04\0\0\x8b\x04\0\0\x20\x10\x01\0\
\x10\0\0\0\x54\x04\0\0\xba\x04\0\0\x07\xe0\0\0\x18\0\0\0\x54\x04\0\0\xba\x04\0\
\0\x05\xe0\0\0\x28\0\0\0\x54\x04\0\0\0\0\0\0\0\0\0\0\x40\0\0\0\x54\x04\0\0\xd4\
\x04\0\0\x02\xe4\0\0\x60\0\0\0\x54\x04\0\0\xff\x04\0\0\x02\xd8\x01\0\xb8\x09\0\
\0\x03\0\0\0\0\0\0\0\x54\x04\0\0\x24\x05\0\0\x05\xe8\x01\0\x08\0\0\0\x54\x04\0\
\0\x7e\x05\0\0\x09\xf0\x01\0\x10\0\0\0\x54\x04\0\0\x24\x05\0\0\x05\xe8\x01\0\
\xd1\x09\0\0\x06\0\0\0\0\0\0\0\x54\x04\0\0\xb5\x05\0\0\x20\x38\x01\0\x10\0\0\0\
\x54\x04\0\0\xba\x04\0\0\x07\xe0\0\0\x18\0\0\0\x54\x04\0\0\xba\x04\0\0\x05\xe0\
\0\0\x28\0\0\0\x54\x04\0\0\0\0\0\0\0\0\0\0\x40\0\0\0\x54\x04\0\0\xd4\x04\0\0\
\x02\xe4\0\0\x60\0\0\0\x54\x04\0\0\xe3\x05\0\0\x05\x04\x02\0\xe7\x09\0\0\x03\0\
\0\0\0\0\0\0\x54\x04\0\0\0\x06\0\0\x05\x1c\x02\0\x08\0\0\0\x54\x04\0\0\x7e\x05\
\0\0\x09\x24\x02\0\x10\0\0\0\x54\x04\0\0\0\x06\0\0\x05\x1c\x02\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x01\0\0\0\x03\0\0\0\x20\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\x40\0\0\0\0\0\0\0\x13\x02\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x01\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\x09\0\0\0\x02\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x58\
\x02\0\0\0\0\0\0\xe8\x02\0\0\0\0\0\0\x01\0\0\0\0\0\0\0\x08\0\0\0\0\0\0\0\x18\0\
\0\0\0\0\0\0\x11\0\0\0\x01\0\0\0\x06\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x40\x05\0\0\
\0\0\0\0\x58\x03\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x08\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\x17\0\0\0\x01\0\0\0\x06\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x98\x08\0\0\0\0\0\0\x70\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x08\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x2e\0\0\0\x01\
\0\0\0\x06\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x08\x09\0\0\0\0\0\0\x20\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\x08\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x47\0\0\0\x01\0\0\0\x06\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\x28\x09\0\0\0\0\0\0\x70\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\0\x08\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x5d\0\0\0\x01\0\0\0\x06\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\x98\x09\0\0\0\0\0\0\x20\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x08\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\x76\0\0\0\x01\0\0\0\x03\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\xb8\x09\0\0\0\0\0\0\x04\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\x7e\0\0\0\x01\0\0\0\x03\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xc0\x09\0\0\0\
\0\0\0\x48\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x08\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x84\
\0\0\0\x08\0\0\0\x03\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x08\x0a\0\0\0\0\0\0\x6c\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\x04\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x8c\x01\0\0\x09\0\
\0\0\x40\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x08\x0a\0\0\0\0\0\0\x60\0\0\0\0\0\0\0\
\x02\0\0\0\x03\0\0\0\x08\0\0\0\0\0\0\0\x10\0\0\0\0\0\0\0\x96\x01\0\0\x09\0\0\0\
\x40\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x68\x0a\0\0\0\0\0\0\x10\0\0\0\0\0\0\0\x02\0\
\0\0\x04\0\0\0\x08\0\0\0\0\0\0\0\x10\0\0\0\0\0\0\0\xb1\x01\0\0\x09\0\0\0\x40\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x78\x0a\0\0\0\0\0\0\x10\0\0\0\0\0\0\0\x02\0\0\0\
\x05\0\0\0\x08\0\0\0\0\0\0\0\x10\0\0\0\0\0\0\0\xce\x01\0\0\x09\0\0\0\x40\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\x88\x0a\0\0\0\0\0\0\x10\0\0\0\0\0\0\0\x02\0\0\0\x06\0\
\0\0\x08\0\0\0\0\0\0\0\x10\0\0\0\0\0\0\0\xe8\x01\0\0\x09\0\0\0\x40\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\x98\x0a\0\0\0\0\0\0\x10\0\0\0\0\0\0\0\x02\0\0\0\x07\0\0\0\
\x08\0\0\0\0\0\0\0\x10\0\0\0\0\0\0\0\x05\x02\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\xa8\x0a\0\0\0\0\0\0\x88\x12\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x08\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\x0a\x02\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\x30\x1d\0\0\0\0\0\0\x90\x04\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x08\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0";

	*sz = sizeof(data) - 1;
	return (const void *)data;
}

#ifdef __cplusplus
struct biolatency_bpf *biolatency_bpf::open(const struct bpf_object_open_opts *opts) { return biolatency_bpf__open_opts(opts); }
struct biolatency_bpf *biolatency_bpf::open_and_load() { return biolatency_bpf__open_and_load(); }
int biolatency_bpf::load(struct biolatency_bpf *skel) { return biolatency_bpf__load(skel); }
int biolatency_bpf::attach(struct biolatency_bpf *skel) { return biolatency_bpf__attach(skel); }
void biolatency_bpf::detach(struct biolatency_bpf *skel) { biolatency_bpf__detach(skel); }
void biolatency_bpf::destroy(struct biolatency_bpf *skel) { biolatency_bpf__destroy(skel); }
const void *biolatency_bpf::elf_bytes(size_t *sz) { return biolatency_bpf__elf_bytes(sz); }
#endif /* __cplusplus */

__attribute__((unused)) static void
biolatency_bpf__assert(struct biolatency_bpf *s __attribute__((unused)))
{
#ifdef __cplusplus
#define _Static_assert static_assert
#endif
#ifdef __cplusplus
#undef _Static_assert
#endif
}

#endif /* __BIOLATENCY_BPF_SKEL_H__ */