/* spoa-server: processing Python
 *
 * Copyright 2018 OZON / Thierry Fournier <thierry.fournier@ozon.io>
 * Copyright (C) 2020  Gilchrist Dadaglo <gilchrist@dadaglo.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 * This program is provided in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 */

/*
 *	Define PY_SSIZE_T_CLEAN before including Python.h
 *	as per https://docs.python.org/3/c-api/arg.html and https://docs.python.org/2/c-api/arg.html
 */
#define PY_SSIZE_T_CLEAN

#include <Python.h>

#include <arpa/inet.h>

#include <errno.h>
#include <string.h>
#include <limits.h>

#include "spoa.h"
#include "ps_python.h"

/* Embedding python documentation:
 *
 * https://docs.python.org/2/extending/embedding.html
 * https://docs.python.org/2/extending/extending.html#extending-python-with-c-or-c
 * https://docs.python.org/2/extending/extending.html#calling-python-functions-from-c
 */

static PyObject *module_ipaddress;
static PyObject *ipv4_address;
static PyObject *ipv6_address;
static PyObject *spoa_error;
static PyObject *empty_tuple;
static struct worker *worker;

static int ps_python_start_worker(struct worker *w);
static int ps_python_load_file(struct worker *w, const char *file);
static int ps_python_exec_message(struct worker *w, void *ref, int nargs, struct spoe_kv *args);

static struct ps ps_python_bindings = {
	.init_worker = ps_python_start_worker,
	.load_file = ps_python_load_file,
	.exec_message = ps_python_exec_message,
	.ext = ".py",
};

static int ps_python_check_overflow(Py_ssize_t len)
{
	/* There might be an overflow when converting from Py_ssize_t to int.
	 * This function will catch those cases.
	 * Also, spoa "struct chunk" is limited to int size.
	 * We should not send data bigger than it can handle.
	 */
	if (len >= (Py_ssize_t)INT_MAX) {
		PyErr_Format(spoa_error,
				"%zd is over 2GB. Please split in smaller pieces.", \
				len);
		return -1;
	} else {
		return Py_SAFE_DOWNCAST(len, Py_ssize_t, int);
	}
}

#if IS_PYTHON_3K
static PyObject *module_spoa;
static PyObject *PyInit_spoa_module(void);
#endif /* IS_PYTHON_3K */

static PyObject *ps_python_register_message(PyObject *self, PyObject *args)
{
	const char *name;
	PyObject *ref;

	if (!PyArg_ParseTuple(args, "sO!", &name, &PyFunction_Type, &ref))
		return NULL;
	Py_XINCREF(ref); /* because the function is internally referenced */

	ps_register_message(&ps_python_bindings, name, (void *)ref);

	Py_RETURN_NONE;
}

static PyObject *ps_python_set_var_null(PyObject *self, PyObject *args)
{
	const char *name;
	Py_ssize_t name_len;
	int name_len_i;
	int scope;

	if (!PyArg_ParseTuple(args, "s#i", &name, &name_len, &scope))
		return NULL;
	name_len_i = ps_python_check_overflow(name_len);
	if (name_len_i == -1)
		return NULL;
	if (!set_var_null(worker, name, name_len_i, scope)) {
		PyErr_SetString(spoa_error, "No more memory space available");
		return NULL;
	}
	Py_RETURN_NONE;
}

static PyObject *ps_python_set_var_boolean(PyObject *self, PyObject *args)
{
	const char *name;
	Py_ssize_t name_len;
	int scope;
	int value;
	int name_len_i;

	if (!PyArg_ParseTuple(args, "s#ii", &name, &name_len, &scope, &value))
		return NULL;
	name_len_i = ps_python_check_overflow(name_len);
	if (name_len_i == -1)
		return NULL;
	if (!set_var_bool(worker, name, name_len_i, scope, value)) {
		PyErr_SetString(spoa_error, "No more memory space available");
		return NULL;
	}
	Py_RETURN_NONE;
}

static PyObject *ps_python_set_var_int32(PyObject *self, PyObject *args)
{
	const char *name;
	Py_ssize_t name_len;
	int scope;
	int32_t value;
	int name_len_i;

	if (!PyArg_ParseTuple(args, "s#ii", &name, &name_len, &scope, &value))
		return NULL;
	name_len_i = ps_python_check_overflow(name_len);
	if (name_len_i == -1)
		return NULL;
	if (!set_var_int32(worker, name, name_len_i, scope, value)) {
		PyErr_SetString(spoa_error, "No more memory space available");
		return NULL;
	}
	Py_RETURN_NONE;
}

static PyObject *ps_python_set_var_uint32(PyObject *self, PyObject *args)
{
	const char *name;
	Py_ssize_t name_len;
	int scope;
	uint32_t value;
	int name_len_i;

	if (!PyArg_ParseTuple(args, "s#iI", &name, &name_len, &scope, &value))
		return NULL;
	name_len_i = ps_python_check_overflow(name_len);
	if (name_len_i == -1)
		return NULL;
	if (!set_var_uint32(worker, name, name_len_i, scope, value)) {
		PyErr_SetString(spoa_error, "No more memory space available");
		return NULL;
	}
	Py_RETURN_NONE;
}

static PyObject *ps_python_set_var_int64(PyObject *self, PyObject *args)
{
	const char *name;
	Py_ssize_t name_len;
	int scope;
	int64_t value;
	int name_len_i;

	if (!PyArg_ParseTuple(args, "s#il", &name, &name_len, &scope, &value))
		return NULL;
	name_len_i = ps_python_check_overflow(name_len);
	if (name_len_i == -1)
		return NULL;
	if (!set_var_int64(worker, name, name_len_i, scope, value)) {
		PyErr_SetString(spoa_error, "No more memory space available");
		return NULL;
	}
	Py_RETURN_NONE;
}

static PyObject *ps_python_set_var_uint64(PyObject *self, PyObject *args)
{
	const char *name;
	Py_ssize_t name_len;
	int scope;
	uint64_t value;
	int name_len_i;

	if (!PyArg_ParseTuple(args, "s#ik", &name, &name_len, &scope, &value))
		return NULL;
	name_len_i = ps_python_check_overflow(name_len);
	if (name_len_i == -1)
		return NULL;
	if (!set_var_uint64(worker, name, name_len_i, scope, value)) {
		PyErr_SetString(spoa_error, "No more memory space available");
		return NULL;
	}
	Py_RETURN_NONE;
}

static PyObject *ps_python_set_var_ipv4(PyObject *self, PyObject *args)
{
	const char *name;
	Py_ssize_t name_len;
	int scope;
	PyObject *ipv4;
	PyObject *value;
	struct in_addr ip;
	int name_len_i;

	if (!PyArg_ParseTuple(args, "s#iO", &name, &name_len, &scope, &ipv4))
		return NULL;
	name_len_i = ps_python_check_overflow(name_len);
	if (name_len_i == -1)
		return NULL;
	if (!PyObject_IsInstance(ipv4, ipv4_address)) {
		PyErr_Format(spoa_error, "must be 'IPv4Address', not '%s'", ipv4->ob_type->tp_name);
		return NULL;
	}
	/* Execute packed ... I think .. */
	value = PyObject_GetAttrString(ipv4, "packed");
	if (value == NULL)
		return NULL;
	if (PY_STRING_GET_SIZE(value) != sizeof(ip)) {
		PyErr_Format(spoa_error, "IPv4 manipulation internal error");
		return NULL;
	}
	memcpy(&ip, PY_STRING_AS_STRING(value), PY_STRING_GET_SIZE(value));
	if (!set_var_ipv4(worker, name, name_len_i, scope, &ip)) {
		PyErr_SetString(spoa_error, "No more memory space available");
		return NULL;
	}
	/* Once we set the IP value in the worker, we don't need it anymore... */
	Py_XDECREF(value);
	Py_RETURN_NONE;
}

static PyObject *ps_python_set_var_ipv6(PyObject *self, PyObject *args)
{
	const char *name;
	Py_ssize_t name_len;
	int scope;
	PyObject *ipv6;
	PyObject *value;
	struct in6_addr ip;
	int name_len_i;

	if (!PyArg_ParseTuple(args, "s#iO", &name, &name_len, &scope, &ipv6))
		return NULL;
	name_len_i = ps_python_check_overflow(name_len);
	if (name_len_i == -1)
		return NULL;
	if (!PyObject_IsInstance(ipv6, ipv6_address)) {
		PyErr_Format(spoa_error, "must be 'IPv6Address', not '%s'", ipv6->ob_type->tp_name);
		return NULL;
	}
	/* Execute packed ... I think .. */
	value = PyObject_GetAttrString(ipv6, "packed");
	if (value == NULL)
		return NULL;
	if (PY_STRING_GET_SIZE(value) != sizeof(ip)) {
		PyErr_Format(spoa_error, "IPv6 manipulation internal error");
		return NULL;
	}
	memcpy(&ip, PY_STRING_AS_STRING(value), PY_STRING_GET_SIZE(value));
	if (!set_var_ipv6(worker, name, name_len_i, scope, &ip)) {
		PyErr_SetString(spoa_error, "No more memory space available");
		return NULL;
	}
	/* Once we set the IP value in the worker, we don't need it anymore... */
	Py_XDECREF(value);
	Py_RETURN_NONE;
}

static PyObject *ps_python_set_var_str(PyObject *self, PyObject *args)
{
	const char *name;
	Py_ssize_t name_len;
	int scope;
	const char *value;
	Py_ssize_t value_len;
	int name_len_i;
	int value_len_i;

	if (!PyArg_ParseTuple(args, "s#is#", &name, &name_len, &scope, &value, &value_len))
		return NULL;
	name_len_i = ps_python_check_overflow(name_len);
	value_len_i = ps_python_check_overflow(value_len);
	if (name_len_i == -1 || value_len_i == -1)
		return NULL;
	if (!set_var_string(worker, name, name_len_i, scope, value, value_len_i)) {
		PyErr_SetString(spoa_error, "No more memory space available");
		return NULL;
	}
	Py_RETURN_NONE;
}

static PyObject *ps_python_set_var_bin(PyObject *self, PyObject *args)
{
	const char *name;
	Py_ssize_t name_len;
	int scope;
	const char *value;
	Py_ssize_t value_len;
	int name_len_i;
	int value_len_i;

	if (!PyArg_ParseTuple(args, "s#is#", &name, &name_len, &scope, &value, &value_len))
		return NULL;
	name_len_i = ps_python_check_overflow(name_len);
	value_len_i = ps_python_check_overflow(value_len);
	if (name_len_i == -1 || value_len_i == -1)
		return NULL;
	if (!set_var_bin(worker, name, name_len_i, scope, value, value_len_i)) {
		PyErr_SetString(spoa_error, "No more memory space available");
		return NULL;
	}
	Py_RETURN_NONE;
}


static PyMethodDef spoa_methods[] = {
	{"register_message", ps_python_register_message, METH_VARARGS,
	 "Register binding for SPOA message."},
	{"set_var_null", ps_python_set_var_null, METH_VARARGS,
	 "Set SPOA NULL variable"},
	{"set_var_boolean", ps_python_set_var_boolean, METH_VARARGS,
	 "Set SPOA boolean variable"},
	{"set_var_int32", ps_python_set_var_int32, METH_VARARGS,
	 "Set SPOA int32 variable"},
	{"set_var_uint32", ps_python_set_var_uint32, METH_VARARGS,
	 "Set SPOA uint32 variable"},
	{"set_var_int64", ps_python_set_var_int64, METH_VARARGS,
	 "Set SPOA int64 variable"},
	{"set_var_uint64", ps_python_set_var_uint64, METH_VARARGS,
	 "Set SPOA uint64 variable"},
	{"set_var_ipv4", ps_python_set_var_ipv4, METH_VARARGS,
	 "Set SPOA ipv4 variable"},
	{"set_var_ipv6", ps_python_set_var_ipv6, METH_VARARGS,
	 "Set SPOA ipv6 variable"},
	{"set_var_str", ps_python_set_var_str, METH_VARARGS,
	 "Set SPOA str variable"},
	{"set_var_bin", ps_python_set_var_bin, METH_VARARGS,
	 "Set SPOA bin variable"},
	{ /* end */ }
};

#if IS_PYTHON_3K
static struct PyModuleDef spoa_module_definition = {
	PyModuleDef_HEAD_INIT,                  /* m_base     */
	"spoa",                                 /* m_name     */
	"HAProxy SPOA module for python",       /* m_doc      */
	-1,                                     /* m_size     */
	spoa_methods,                           /* m_methods  */
	NULL,                                   /* m_slots    */
	NULL,                                   /* m_traverse */
	NULL,                                   /* m_clear    */
	NULL                                    /* m_free     */
};

static PyObject *PyInit_spoa_module(void)
{
	return module_spoa;
}
#endif /* IS_PYTHON_3K */

static int ps_python_start_worker(struct worker *w)
{
	PyObject *m;
	PyObject *module_name;
	PyObject *value;
	int ret;

#if IS_PYTHON_27
	Py_SetProgramName("spoa-server");
#endif /* IS_PYTHON_27 */
#if IS_PYTHON_3K
	Py_SetProgramName(Py_DecodeLocale("spoa-server", NULL));
	PyImport_AppendInittab("spoa", &PyInit_spoa_module);
#endif /* IS_PYTHON_3K */

	Py_Initialize();

	module_name = PY_STRING_FROM_STRING("ipaddress");
	if (module_name == NULL) {
		PyErr_Print();
		return 0;
	}

	module_ipaddress = PyImport_Import(module_name);
	Py_DECREF(module_name);
	if (module_ipaddress == NULL) {
		PyErr_Print();
		return 0;
	}

	ipv4_address = PyObject_GetAttrString(module_ipaddress, "IPv4Address");
	if (ipv4_address == NULL) {
		Py_DECREF(module_ipaddress);
		PyErr_Print();
		return 0;
	}

	ipv6_address = PyObject_GetAttrString(module_ipaddress, "IPv6Address");
	if (ipv6_address == NULL) {
		Py_DECREF(ipv4_address);
		Py_DECREF(module_ipaddress);
		PyErr_Print();
		return 0;
	}

	PY_INIT_MODULE(m, "spoa", spoa_methods, &spoa_module_definition);
	if (m == NULL) {
		Py_DECREF(ipv4_address);
		Py_DECREF(ipv6_address);
		Py_DECREF(module_ipaddress);
		PyErr_Print();
		return 0;
	}

	spoa_error = PyErr_NewException("spoa.error", NULL, NULL);
	 /* PyModule_AddObject will steal the reference to spoa_error
	 * in case of success only
	 * We need to increment the counters to continue using it
	 * but cleanup in case of failure
	 */
	Py_INCREF(spoa_error);
	ret = PyModule_AddObject(m, "error", spoa_error);
	if (ret == -1) {
		Py_DECREF(m);
		Py_DECREF(spoa_error);
		PyErr_Print();
		return 0;
	}


	value = PyLong_FromLong(SPOE_SCOPE_PROC);
	if (value == NULL) {
		PyErr_Print();
		return 0;
	}

	ret = PyModule_AddObject(m, "scope_proc", value);
	if (ret == -1) {
		Py_DECREF(m);
		Py_DECREF(value);
		PyErr_Print();
		return 0;
	}

	value = PyLong_FromLong(SPOE_SCOPE_SESS);
	if (value == NULL) {
		Py_DECREF(m);
		PyErr_Print();
		return 0;
	}

	ret = PyModule_AddObject(m, "scope_sess", value);
	if (ret == -1) {
		Py_DECREF(m);
		Py_DECREF(value);
		PyErr_Print();
		return 0;
	}

	value = PyLong_FromLong(SPOE_SCOPE_TXN);
	if (value == NULL) {
		Py_DECREF(m);
		PyErr_Print();
		return 0;
	}

	ret = PyModule_AddObject(m, "scope_txn", value);
	if (ret == -1) {
		Py_DECREF(m);
		Py_DECREF(value);
		PyErr_Print();
		return 0;
	}

	value = PyLong_FromLong(SPOE_SCOPE_REQ);
	if (value == NULL) {
		Py_DECREF(m);
		PyErr_Print();
		return 0;
	}

	ret = PyModule_AddObject(m, "scope_req", value);
	if (ret == -1) {
		Py_DECREF(m);
		Py_DECREF(value);
		PyErr_Print();
		return 0;
	}

	value = PyLong_FromLong(SPOE_SCOPE_RES);
	if (value == NULL) {
		Py_DECREF(m);
		PyErr_Print();
		return 0;
	}

	ret = PyModule_AddObject(m, "scope_res", value);
	if (ret == -1) {
		Py_DECREF(m);
		Py_DECREF(value);
		PyErr_Print();
		return 0;
	}

	empty_tuple = PyTuple_New(0);
	if (empty_tuple == NULL) {
		PyErr_Print();
		return 0;
	}

#if IS_PYTHON_3K
	module_spoa = m;
#endif /* IS_PYTHON_3K */
	worker = w;
	return 1;
}

static int ps_python_load_file(struct worker *w, const char *file)
{
	FILE *fp;
	int ret;

	fp = fopen(file, "r");
	if (fp == NULL) {
		LOG("python: Cannot read file \"%s\": %s", file, strerror(errno));
		return 0;
	}

	ret = PyRun_SimpleFile(fp, file);
	fclose(fp);
	if (ret != 0) {
		PyErr_Print();
		return 0;
	}

	return 1;
}

static int ps_python_exec_message(struct worker *w, void *ref, int nargs, struct spoe_kv *args)
{
	int i;
	PyObject *python_ref = ref;
	PyObject *fkw;
	PyObject *kw_args;
	PyObject *result;
	PyObject *ent;
	PyObject *key;
	PyObject *value;
	PyObject *func;
	int ret;
	char ipbuf[64];
	const char *p;
	PyObject *ip_dict;
	PyObject *ip_name;
	PyObject *ip_value;

	/* Dict containing arguments */

	kw_args = PyList_New(0);
	if (kw_args == NULL) {
		PyErr_Print();
		return 0;
	}

	for (i = 0; i < nargs; i++) {

		/* New dict containing one argument */

		ent = PyDict_New();
		if (ent == NULL) {
			Py_DECREF(kw_args);
			PyErr_Print();
			return 0;
		}

		/* Create the name entry */

		key = PY_STRING_FROM_STRING("name");
		if (key == NULL) {
			Py_DECREF(kw_args);
			Py_DECREF(ent);
			PyErr_Print();
			return 0;
		}

		value = PY_STRING_FROM_STRING_AND_SIZE(args[i].name.str, args[i].name.len);
		if (value == NULL) {
			Py_DECREF(kw_args);
			Py_DECREF(ent);
			Py_DECREF(key);
			PyErr_Print();
			return 0;
		}

		ret = PyDict_SetItem(ent, key, value);
		Py_DECREF(key);
		Py_DECREF(value);
		if (ret == -1) {
			Py_DECREF(kw_args);
			Py_DECREF(ent);
			PyErr_Print();
			return 0;
		}

		/* Create the value entry */

		key = PY_STRING_FROM_STRING("value");
		if (key == NULL) {
			Py_DECREF(kw_args);
			Py_DECREF(ent);
			PyErr_Print();
			return 0;
		}

		switch (args[i].value.type) {
		case SPOE_DATA_T_NULL:
			Py_INCREF(Py_None);
			value = Py_None;
			break;
		case SPOE_DATA_T_BOOL:
			value = PyBool_FromLong(args[i].value.u.boolean);
			break;
		case SPOE_DATA_T_INT32:
			value = PyLong_FromLong(args[i].value.u.sint32);
			break;
		case SPOE_DATA_T_UINT32:
			value = PyLong_FromLong(args[i].value.u.uint32);
			break;
		case SPOE_DATA_T_INT64:
			value = PyLong_FromLong(args[i].value.u.sint64);
			break;
		case SPOE_DATA_T_UINT64:
			value = PyLong_FromUnsignedLong(args[i].value.u.uint64);
			break;
		case SPOE_DATA_T_IPV4:
		case SPOE_DATA_T_IPV6:
			if (args[i].value.type == SPOE_DATA_T_IPV4)
				p = inet_ntop(AF_INET, &args[i].value.u.ipv4, ipbuf, 64);
			else
				p = inet_ntop(AF_INET6, &args[i].value.u.ipv6, ipbuf, 64);
			if (!p)
				strcpy(ipbuf, "0.0.0.0");

			func = PyObject_GetAttrString(module_ipaddress, "ip_address");
			if (func == NULL) {
				Py_DECREF(kw_args);
				Py_DECREF(ent);
				Py_DECREF(key);
				PyErr_Print();
				return 0;
			}
			ip_dict = PyDict_New();
			if (ip_dict == NULL) {
				Py_DECREF(kw_args);
				Py_DECREF(ent);
				Py_DECREF(key);
				Py_DECREF(func);
				PyErr_Print();
				return 0;
			}
			ip_name = PY_STRING_FROM_STRING("address");
			if (ip_name == NULL) {
				Py_DECREF(kw_args);
				Py_DECREF(ent);
				Py_DECREF(key);
				Py_DECREF(func);
				Py_DECREF(ip_dict);
				PyErr_Print();
				return 0;
			}
			ip_value = PyUnicode_FromString(ipbuf);
			if (ip_value == NULL) {
				Py_DECREF(kw_args);
				Py_DECREF(ent);
				Py_DECREF(key);
				Py_DECREF(func);
				Py_DECREF(ip_dict);
				Py_DECREF(ip_name);
				PyErr_Print();
				return 0;
			}
			ret = PyDict_SetItem(ip_dict, ip_name, ip_value);
			Py_DECREF(ip_name);
			Py_DECREF(ip_value);
			if (ret == -1) {
				Py_DECREF(kw_args);
				Py_DECREF(ent);
				Py_DECREF(key);
				Py_DECREF(func);
				Py_DECREF(ip_dict);
				PyErr_Print();
				return 0;
			}
			value = PyObject_Call(func, empty_tuple, ip_dict);
			Py_DECREF(func);
			Py_DECREF(ip_dict);
			break;

		case SPOE_DATA_T_STR:
			value = PY_STRING_FROM_STRING_AND_SIZE(args[i].value.u.buffer.str, args[i].value.u.buffer.len);
			break;
		case SPOE_DATA_T_BIN:
			value = PY_BYTES_FROM_STRING_AND_SIZE(args[i].value.u.buffer.str, args[i].value.u.buffer.len);
			break;
		default:
			Py_INCREF(Py_None);
			value = Py_None;
			break;
		}
		if (value == NULL) {
			Py_DECREF(kw_args);
			Py_DECREF(ent);
			Py_DECREF(key);
			PyErr_Print();
			return 0;
		}

		ret = PyDict_SetItem(ent, key, value);
		Py_DECREF(key);
		Py_DECREF(value);
		if (ret == -1) {
			Py_DECREF(kw_args);
			Py_DECREF(ent);
			PyErr_Print();
			return 0;
		}

		/* Add dict to the list */

		ret = PyList_Append(kw_args, ent);
		Py_DECREF(ent);
		if (ret == -1) {
			Py_DECREF(kw_args);
			PyErr_Print();
			return 0;
		}
	}

	/* Dictionary { args = <list-of-args> } for the function */

	fkw = PyDict_New();
	if (fkw == NULL) {
		Py_DECREF(kw_args);
		PyErr_Print();
		return 0;
	}

	key = PY_STRING_FROM_STRING("args");
	if (key == NULL) {
		Py_DECREF(kw_args);
		Py_DECREF(fkw);
		PyErr_Print();
		return 0;
	}

	ret = PyDict_SetItem(fkw, key, kw_args);
	Py_DECREF(kw_args);
	Py_DECREF(key);
	if (ret == -1) {
		Py_DECREF(fkw);
		PyErr_Print();
		return 0;
	}

	result = PyObject_Call(python_ref, empty_tuple, fkw);
	Py_DECREF(fkw);
	if (result == NULL) {
		PyErr_Print();
		return 0;
	}
	Py_DECREF(result);

	return 1;
}

__attribute__((constructor))
static void __ps_python_init(void)
{
	ps_register(&ps_python_bindings);
}
