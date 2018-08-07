
/* Python wrapper functions auto-generated by pidl */
#define PY_SSIZE_T_CLEAN 1 /* We use Py_ssize_t for PyArg_ParseTupleAndKeywords */
#include <Python.h>
#include "python/py3compat.h"
#include "includes.h"
#include <pytalloc.h>
#include "librpc/rpc/pyrpc.h"
#include "librpc/rpc/pyrpc_util.h"
#include "bin/default/librpc/gen_ndr/ndr_idmap.h"
#include "bin/default/librpc/gen_ndr/ndr_idmap_c.h"

/*
 * These functions are here to ensure they can be optimized out by
 * the compiler based on the constant input values
 */

static inline unsigned long long ndr_sizeof2uintmax(size_t var_size)
{
	switch (var_size) {
	case 8:
		return UINT64_MAX;
	case 4:
		return UINT32_MAX;
	case 2:
		return UINT16_MAX;
	case 1:
		return UINT8_MAX;
	}

	return 0;
}

static inline long long ndr_sizeof2intmax(size_t var_size)
{
	switch (var_size) {
	case 8:
		return INT64_MAX;
	case 4:
		return INT32_MAX;
	case 2:
		return INT16_MAX;
	case 1:
		return INT8_MAX;
	}

	return 0;
}

static inline PyObject *ndr_PyLong_FromLongLong(long long v)
{
	if (v > LONG_MAX || v < LONG_MIN) {
		return PyLong_FromLongLong(v);
	} else {
		return PyInt_FromLong(v);
	}
}

static inline PyObject *ndr_PyLong_FromUnsignedLongLong(unsigned long long v)
{
	if (v > LONG_MAX) {
		return PyLong_FromUnsignedLongLong(v);
	} else {
		return PyInt_FromLong(v);
	}
}

#include "librpc/gen_ndr/security.h"
static PyTypeObject unixid_Type;
static PyTypeObject id_map_Type;

static PyTypeObject *BaseObject_Type;
static PyTypeObject *dom_sid_Type;

static PyObject *py_unixid_get_id(PyObject *obj, void *closure)
{
	struct unixid *object = (struct unixid *)pytalloc_get_ptr(obj);
	PyObject *py_id;
	py_id = ndr_PyLong_FromUnsignedLongLong((uint32_t)object->id);
	return py_id;
}

static int py_unixid_set_id(PyObject *py_obj, PyObject *value, void *closure)
{
	struct unixid *object = (struct unixid *)pytalloc_get_ptr(py_obj);
	if (value == NULL) {
		PyErr_Format(PyExc_AttributeError, "Cannot delete NDR object: struct object->id");
		return -1;
	}
	{
		const unsigned long long uint_max = ndr_sizeof2uintmax(sizeof(object->id));
		if (PyLong_Check(value)) {
			unsigned long long test_var;
			test_var = PyLong_AsUnsignedLongLong(value);
			if (PyErr_Occurred() != NULL) {
				return -1;
			}
			if (test_var > uint_max) {
				PyErr_Format(PyExc_OverflowError, "Expected type %s or %s within range 0 - %llu, got %llu",\
				  PyInt_Type.tp_name, PyLong_Type.tp_name, uint_max, test_var);
				return -1;
			}
			object->id = test_var;
		} else if (PyInt_Check(value)) {
			long test_var;
			test_var = PyInt_AsLong(value);
			if (test_var < 0 || test_var > uint_max) {
				PyErr_Format(PyExc_OverflowError, "Expected type %s or %s within range 0 - %llu, got %ld",\
				  PyInt_Type.tp_name, PyLong_Type.tp_name, uint_max, test_var);
				return -1;
			}
			object->id = test_var;
		} else {
			PyErr_Format(PyExc_TypeError, "Expected type %s or %s",\
			  PyInt_Type.tp_name, PyLong_Type.tp_name);
			return -1;
		}
	}
	return 0;
}

static PyObject *py_unixid_get_type(PyObject *obj, void *closure)
{
	struct unixid *object = (struct unixid *)pytalloc_get_ptr(obj);
	PyObject *py_type;
	py_type = PyInt_FromLong((uint16_t)object->type);
	return py_type;
}

static int py_unixid_set_type(PyObject *py_obj, PyObject *value, void *closure)
{
	struct unixid *object = (struct unixid *)pytalloc_get_ptr(py_obj);
	if (value == NULL) {
		PyErr_Format(PyExc_AttributeError, "Cannot delete NDR object: struct object->type");
		return -1;
	}
	{
		const unsigned long long uint_max = ndr_sizeof2uintmax(sizeof(object->type));
		if (PyLong_Check(value)) {
			unsigned long long test_var;
			test_var = PyLong_AsUnsignedLongLong(value);
			if (PyErr_Occurred() != NULL) {
				return -1;
			}
			if (test_var > uint_max) {
				PyErr_Format(PyExc_OverflowError, "Expected type %s or %s within range 0 - %llu, got %llu",\
				  PyInt_Type.tp_name, PyLong_Type.tp_name, uint_max, test_var);
				return -1;
			}
			object->type = test_var;
		} else if (PyInt_Check(value)) {
			long test_var;
			test_var = PyInt_AsLong(value);
			if (test_var < 0 || test_var > uint_max) {
				PyErr_Format(PyExc_OverflowError, "Expected type %s or %s within range 0 - %llu, got %ld",\
				  PyInt_Type.tp_name, PyLong_Type.tp_name, uint_max, test_var);
				return -1;
			}
			object->type = test_var;
		} else {
			PyErr_Format(PyExc_TypeError, "Expected type %s or %s",\
			  PyInt_Type.tp_name, PyLong_Type.tp_name);
			return -1;
		}
	}
	return 0;
}

static PyGetSetDef py_unixid_getsetters[] = {
	{
		.name = discard_const_p(char, "id"),
		.get = py_unixid_get_id,
		.set = py_unixid_set_id,
		.doc = discard_const_p(char, "PIDL-generated element of base type uint32")
	},
	{
		.name = discard_const_p(char, "type"),
		.get = py_unixid_get_type,
		.set = py_unixid_set_type,
		.doc = discard_const_p(char, "PIDL-generated element of base type id_type")
	},
	{ .name = NULL }
};

static PyObject *py_unixid_new(PyTypeObject *type, PyObject *args, PyObject *kwargs)
{
	return pytalloc_new(struct unixid, type);
}

static PyObject *py_unixid_ndr_pack(PyObject *py_obj)
{
	struct unixid *object = (struct unixid *)pytalloc_get_ptr(py_obj);
	PyObject *ret = NULL;
	DATA_BLOB blob;
	enum ndr_err_code err;
	TALLOC_CTX *tmp_ctx = talloc_new(pytalloc_get_mem_ctx(py_obj));
	if (tmp_ctx == NULL) {
		PyErr_SetNdrError(NDR_ERR_ALLOC);
		return NULL;
	}
	err = ndr_push_struct_blob(&blob, tmp_ctx, object, (ndr_push_flags_fn_t)ndr_push_unixid);
	if (!NDR_ERR_CODE_IS_SUCCESS(err)) {
		TALLOC_FREE(tmp_ctx);
		PyErr_SetNdrError(err);
		return NULL;
	}

	ret = PyBytes_FromStringAndSize((char *)blob.data, blob.length);
	TALLOC_FREE(tmp_ctx);
	return ret;
}

static PyObject *py_unixid_ndr_unpack(PyObject *py_obj, PyObject *args, PyObject *kwargs)
{
	struct unixid *object = (struct unixid *)pytalloc_get_ptr(py_obj);
	DATA_BLOB blob;
	Py_ssize_t blob_length = 0;
	enum ndr_err_code err;
	const char * const kwnames[] = { "data_blob", "allow_remaining", NULL };
	PyObject *allow_remaining_obj = NULL;
	bool allow_remaining = false;

	if (!PyArg_ParseTupleAndKeywords(args, kwargs, PYARG_BYTES_LEN "|O:__ndr_unpack__",
		discard_const_p(char *, kwnames),
		&blob.data, &blob_length,
		&allow_remaining_obj)) {
		return NULL;
	}
	blob.length = blob_length;

	if (allow_remaining_obj && PyObject_IsTrue(allow_remaining_obj)) {
		allow_remaining = true;
	}

	if (allow_remaining) {
		err = ndr_pull_struct_blob(&blob, pytalloc_get_mem_ctx(py_obj), object, (ndr_pull_flags_fn_t)ndr_pull_unixid);
	} else {
		err = ndr_pull_struct_blob_all(&blob, pytalloc_get_mem_ctx(py_obj), object, (ndr_pull_flags_fn_t)ndr_pull_unixid);
	}
	if (!NDR_ERR_CODE_IS_SUCCESS(err)) {
		PyErr_SetNdrError(err);
		return NULL;
	}

	Py_RETURN_NONE;
}

static PyObject *py_unixid_ndr_print(PyObject *py_obj)
{
	struct unixid *object = (struct unixid *)pytalloc_get_ptr(py_obj);
	PyObject *ret;
	char *retstr;

	retstr = ndr_print_struct_string(pytalloc_get_mem_ctx(py_obj), (ndr_print_fn_t)ndr_print_unixid, "unixid", object);
	ret = PyStr_FromString(retstr);
	talloc_free(retstr);

	return ret;
}

static PyMethodDef py_unixid_methods[] = {
	{ "__ndr_pack__", (PyCFunction)py_unixid_ndr_pack, METH_NOARGS, "S.ndr_pack(object) -> blob\nNDR pack" },
	{ "__ndr_unpack__", (PyCFunction)py_unixid_ndr_unpack, METH_VARARGS|METH_KEYWORDS, "S.ndr_unpack(class, blob, allow_remaining=False) -> None\nNDR unpack" },
	{ "__ndr_print__", (PyCFunction)py_unixid_ndr_print, METH_NOARGS, "S.ndr_print(object) -> None\nNDR print" },
	{ NULL, NULL, 0, NULL }
};


static PyTypeObject unixid_Type = {
	PyVarObject_HEAD_INIT(NULL, 0)
	.tp_name = "idmap.unixid",
	.tp_getset = py_unixid_getsetters,
	.tp_methods = py_unixid_methods,
	.tp_flags = Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE,
	.tp_new = py_unixid_new,
};


static PyObject *py_id_map_get_sid(PyObject *obj, void *closure)
{
	struct id_map *object = (struct id_map *)pytalloc_get_ptr(obj);
	PyObject *py_sid;
	if (object->sid == NULL) {
		py_sid = Py_None;
		Py_INCREF(py_sid);
	} else {
		py_sid = pytalloc_reference_ex(dom_sid_Type, object->sid, object->sid);
	}
	return py_sid;
}

static int py_id_map_set_sid(PyObject *py_obj, PyObject *value, void *closure)
{
	struct id_map *object = (struct id_map *)pytalloc_get_ptr(py_obj);
	talloc_unlink(pytalloc_get_mem_ctx(py_obj), discard_const(object->sid));
	if (value == NULL) {
		PyErr_Format(PyExc_AttributeError, "Cannot delete NDR object: struct object->sid");
		return -1;
	}
	if (value == Py_None) {
		object->sid = NULL;
	} else {
		object->sid = NULL;
		PY_CHECK_TYPE(dom_sid_Type, value, return -1;);
		if (talloc_reference(pytalloc_get_mem_ctx(py_obj), pytalloc_get_mem_ctx(value)) == NULL) {
			PyErr_NoMemory();
			return -1;
		}
		object->sid = (struct dom_sid *)pytalloc_get_ptr(value);
	}
	return 0;
}

static PyObject *py_id_map_get_xid(PyObject *obj, void *closure)
{
	struct id_map *object = (struct id_map *)pytalloc_get_ptr(obj);
	PyObject *py_xid;
	py_xid = pytalloc_reference_ex(&unixid_Type, pytalloc_get_mem_ctx(obj), &object->xid);
	return py_xid;
}

static int py_id_map_set_xid(PyObject *py_obj, PyObject *value, void *closure)
{
	struct id_map *object = (struct id_map *)pytalloc_get_ptr(py_obj);
	if (value == NULL) {
		PyErr_Format(PyExc_AttributeError, "Cannot delete NDR object: struct object->xid");
		return -1;
	}
	PY_CHECK_TYPE(&unixid_Type, value, return -1;);
	if (talloc_reference(pytalloc_get_mem_ctx(py_obj), pytalloc_get_mem_ctx(value)) == NULL) {
		PyErr_NoMemory();
		return -1;
	}
	object->xid = *(struct unixid *)pytalloc_get_ptr(value);
	return 0;
}

static PyObject *py_id_map_get_status(PyObject *obj, void *closure)
{
	struct id_map *object = (struct id_map *)pytalloc_get_ptr(obj);
	PyObject *py_status;
	py_status = PyInt_FromLong((uint16_t)object->status);
	return py_status;
}

static int py_id_map_set_status(PyObject *py_obj, PyObject *value, void *closure)
{
	struct id_map *object = (struct id_map *)pytalloc_get_ptr(py_obj);
	if (value == NULL) {
		PyErr_Format(PyExc_AttributeError, "Cannot delete NDR object: struct object->status");
		return -1;
	}
	{
		const unsigned long long uint_max = ndr_sizeof2uintmax(sizeof(object->status));
		if (PyLong_Check(value)) {
			unsigned long long test_var;
			test_var = PyLong_AsUnsignedLongLong(value);
			if (PyErr_Occurred() != NULL) {
				return -1;
			}
			if (test_var > uint_max) {
				PyErr_Format(PyExc_OverflowError, "Expected type %s or %s within range 0 - %llu, got %llu",\
				  PyInt_Type.tp_name, PyLong_Type.tp_name, uint_max, test_var);
				return -1;
			}
			object->status = test_var;
		} else if (PyInt_Check(value)) {
			long test_var;
			test_var = PyInt_AsLong(value);
			if (test_var < 0 || test_var > uint_max) {
				PyErr_Format(PyExc_OverflowError, "Expected type %s or %s within range 0 - %llu, got %ld",\
				  PyInt_Type.tp_name, PyLong_Type.tp_name, uint_max, test_var);
				return -1;
			}
			object->status = test_var;
		} else {
			PyErr_Format(PyExc_TypeError, "Expected type %s or %s",\
			  PyInt_Type.tp_name, PyLong_Type.tp_name);
			return -1;
		}
	}
	return 0;
}

static PyGetSetDef py_id_map_getsetters[] = {
	{
		.name = discard_const_p(char, "sid"),
		.get = py_id_map_get_sid,
		.set = py_id_map_set_sid,
		.doc = discard_const_p(char, "PIDL-generated element of base type dom_sid")
	},
	{
		.name = discard_const_p(char, "xid"),
		.get = py_id_map_get_xid,
		.set = py_id_map_set_xid,
		.doc = discard_const_p(char, "PIDL-generated element of base type unixid")
	},
	{
		.name = discard_const_p(char, "status"),
		.get = py_id_map_get_status,
		.set = py_id_map_set_status,
		.doc = discard_const_p(char, "PIDL-generated element of base type id_mapping")
	},
	{ .name = NULL }
};

static PyObject *py_id_map_new(PyTypeObject *type, PyObject *args, PyObject *kwargs)
{
	return pytalloc_new(struct id_map, type);
}

static PyObject *py_id_map_ndr_pack(PyObject *py_obj)
{
	struct id_map *object = (struct id_map *)pytalloc_get_ptr(py_obj);
	PyObject *ret = NULL;
	DATA_BLOB blob;
	enum ndr_err_code err;
	TALLOC_CTX *tmp_ctx = talloc_new(pytalloc_get_mem_ctx(py_obj));
	if (tmp_ctx == NULL) {
		PyErr_SetNdrError(NDR_ERR_ALLOC);
		return NULL;
	}
	err = ndr_push_struct_blob(&blob, tmp_ctx, object, (ndr_push_flags_fn_t)ndr_push_id_map);
	if (!NDR_ERR_CODE_IS_SUCCESS(err)) {
		TALLOC_FREE(tmp_ctx);
		PyErr_SetNdrError(err);
		return NULL;
	}

	ret = PyBytes_FromStringAndSize((char *)blob.data, blob.length);
	TALLOC_FREE(tmp_ctx);
	return ret;
}

static PyObject *py_id_map_ndr_unpack(PyObject *py_obj, PyObject *args, PyObject *kwargs)
{
	struct id_map *object = (struct id_map *)pytalloc_get_ptr(py_obj);
	DATA_BLOB blob;
	Py_ssize_t blob_length = 0;
	enum ndr_err_code err;
	const char * const kwnames[] = { "data_blob", "allow_remaining", NULL };
	PyObject *allow_remaining_obj = NULL;
	bool allow_remaining = false;

	if (!PyArg_ParseTupleAndKeywords(args, kwargs, PYARG_BYTES_LEN "|O:__ndr_unpack__",
		discard_const_p(char *, kwnames),
		&blob.data, &blob_length,
		&allow_remaining_obj)) {
		return NULL;
	}
	blob.length = blob_length;

	if (allow_remaining_obj && PyObject_IsTrue(allow_remaining_obj)) {
		allow_remaining = true;
	}

	if (allow_remaining) {
		err = ndr_pull_struct_blob(&blob, pytalloc_get_mem_ctx(py_obj), object, (ndr_pull_flags_fn_t)ndr_pull_id_map);
	} else {
		err = ndr_pull_struct_blob_all(&blob, pytalloc_get_mem_ctx(py_obj), object, (ndr_pull_flags_fn_t)ndr_pull_id_map);
	}
	if (!NDR_ERR_CODE_IS_SUCCESS(err)) {
		PyErr_SetNdrError(err);
		return NULL;
	}

	Py_RETURN_NONE;
}

static PyObject *py_id_map_ndr_print(PyObject *py_obj)
{
	struct id_map *object = (struct id_map *)pytalloc_get_ptr(py_obj);
	PyObject *ret;
	char *retstr;

	retstr = ndr_print_struct_string(pytalloc_get_mem_ctx(py_obj), (ndr_print_fn_t)ndr_print_id_map, "id_map", object);
	ret = PyStr_FromString(retstr);
	talloc_free(retstr);

	return ret;
}

static PyMethodDef py_id_map_methods[] = {
	{ "__ndr_pack__", (PyCFunction)py_id_map_ndr_pack, METH_NOARGS, "S.ndr_pack(object) -> blob\nNDR pack" },
	{ "__ndr_unpack__", (PyCFunction)py_id_map_ndr_unpack, METH_VARARGS|METH_KEYWORDS, "S.ndr_unpack(class, blob, allow_remaining=False) -> None\nNDR unpack" },
	{ "__ndr_print__", (PyCFunction)py_id_map_ndr_print, METH_NOARGS, "S.ndr_print(object) -> None\nNDR print" },
	{ NULL, NULL, 0, NULL }
};


static PyTypeObject id_map_Type = {
	PyVarObject_HEAD_INIT(NULL, 0)
	.tp_name = "idmap.id_map",
	.tp_getset = py_id_map_getsetters,
	.tp_methods = py_id_map_methods,
	.tp_flags = Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE,
	.tp_new = py_id_map_new,
};

static PyMethodDef idmap_methods[] = {
	{ NULL, NULL, 0, NULL }
};

static struct PyModuleDef moduledef = {
	PyModuleDef_HEAD_INIT,
	.m_name = "idmap",
	.m_doc = "idmap DCE/RPC",
	.m_size = -1,
	.m_methods = idmap_methods,
};
MODULE_INIT_FUNC(idmap)
{
	PyObject *m;
	PyObject *dep_samba_dcerpc_security;
	PyObject *dep_talloc;

	dep_samba_dcerpc_security = PyImport_ImportModule("samba.dcerpc.security");
	if (dep_samba_dcerpc_security == NULL)
		return NULL;

	dep_talloc = PyImport_ImportModule("talloc");
	if (dep_talloc == NULL)
		return NULL;

	BaseObject_Type = (PyTypeObject *)PyObject_GetAttrString(dep_talloc, "BaseObject");
	if (BaseObject_Type == NULL)
		return NULL;

	dom_sid_Type = (PyTypeObject *)PyObject_GetAttrString(dep_samba_dcerpc_security, "dom_sid");
	if (dom_sid_Type == NULL)
		return NULL;

	unixid_Type.tp_base = BaseObject_Type;
	unixid_Type.tp_basicsize = pytalloc_BaseObject_size();

	id_map_Type.tp_base = BaseObject_Type;
	id_map_Type.tp_basicsize = pytalloc_BaseObject_size();

	if (PyType_Ready(&unixid_Type) < 0)
		return NULL;
	if (PyType_Ready(&id_map_Type) < 0)
		return NULL;
#ifdef PY_UNIXID_PATCH
	PY_UNIXID_PATCH(&unixid_Type);
#endif
#ifdef PY_ID_MAP_PATCH
	PY_ID_MAP_PATCH(&id_map_Type);
#endif

	m = PyModule_Create(&moduledef);
	if (m == NULL)
		return NULL;

	PyModule_AddObject(m, "ID_TYPE_NOT_SPECIFIED", PyInt_FromLong((uint16_t)ID_TYPE_NOT_SPECIFIED));
	PyModule_AddObject(m, "ID_TYPE_UID", PyInt_FromLong((uint16_t)ID_TYPE_UID));
	PyModule_AddObject(m, "ID_TYPE_GID", PyInt_FromLong((uint16_t)ID_TYPE_GID));
	PyModule_AddObject(m, "ID_TYPE_BOTH", PyInt_FromLong((uint16_t)ID_TYPE_BOTH));
	PyModule_AddObject(m, "ID_UNKNOWN", PyInt_FromLong((uint16_t)ID_UNKNOWN));
	PyModule_AddObject(m, "ID_MAPPED", PyInt_FromLong((uint16_t)ID_MAPPED));
	PyModule_AddObject(m, "ID_UNMAPPED", PyInt_FromLong((uint16_t)ID_UNMAPPED));
	PyModule_AddObject(m, "ID_EXPIRED", PyInt_FromLong((uint16_t)ID_EXPIRED));
	Py_INCREF((PyObject *)(void *)&unixid_Type);
	PyModule_AddObject(m, "unixid", (PyObject *)(void *)&unixid_Type);
	Py_INCREF((PyObject *)(void *)&id_map_Type);
	PyModule_AddObject(m, "id_map", (PyObject *)(void *)&id_map_Type);
#ifdef PY_MOD_IDMAP_PATCH
	PY_MOD_IDMAP_PATCH(m);
#endif
	return m;

}
