/* spoa-server: processing Python
 *
 * Copyright 2018 OZON / Thierry Fournier <thierry.fournier@ozon.io>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 */

#include <Python.h>

#include <arpa/inet.h>

#include <errno.h>
#include <string.h>

#include "spoa.h"

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
static PyObject *empty_array;
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

static PyObject *ps_python_register_message(PyObject *self, PyObject *args)
{
	const char *name;
	PyObject *ref;

	if (!PyArg_ParseTuple(args, "sO!", &name, &PyFunction_Type, &ref))
		return NULL;
	Py_XINCREF(ref); /* because the function is intenally refrenced */

	ps_register_message(&ps_python_bindings, name, (void *)ref);

	return Py_None;
}

static PyObject *ps_python_set_var_null(PyObject *self, PyObject *args)
{
	const char *name;
	int name_len;
	int scope;

	if (!PyArg_ParseTuple(args, "s#i", &name, &name_len, &scope))
		return NULL;
	if (!set_var_null(worker, name, name_len, scope)) {
		PyErr_SetString(spoa_error, "No space left available");
		return NULL;
	}
	return Py_None;
}

static PyObject *ps_python_set_var_boolean(PyObject *self, PyObject *args)
{
	const char *name;
	int name_len;
	int scope;
	int value;

	if (!PyArg_ParseTuple(args, "s#ii", &name, &name_len, &scope, &value))
		return NULL;
	if (!set_var_bool(worker, name, name_len, scope, value)) {
		PyErr_SetString(spoa_error, "No space left available");
		return NULL;
	}
	return Py_None;
}

static PyObject *ps_python_set_var_int32(PyObject *self, PyObject *args)
{
	const char *name;
	int name_len;
	int scope;
	int32_t value;

	if (!PyArg_ParseTuple(args, "s#ii", &name, &name_len, &scope, &value))
		return NULL;
	if (!set_var_int32(worker, name, name_len, scope, value)) {
		PyErr_SetString(spoa_error, "No space left available");
		return NULL;
	}
	return Py_None;
}

static PyObject *ps_python_set_var_uint32(PyObject *self, PyObject *args)
{
	const char *name;
	int name_len;
	int scope;
	uint32_t value;

	if (!PyArg_ParseTuple(args, "s#iI", &name, &name_len, &scope, &value))
		return NULL;
	if (!set_var_uint32(worker, name, name_len, scope, value)) {
		PyErr_SetString(spoa_error, "No space left available");
		return NULL;
	}
	return Py_None;
}

static PyObject *ps_python_set_var_int64(PyObject *self, PyObject *args)
{
	const char *name;
	int name_len;
	int scope;
	int64_t value;

	if (!PyArg_ParseTuple(args, "s#il", &name, &name_len, &scope, &value))
		return NULL;
	if (!set_var_int64(worker, name, name_len, scope, value)) {
		PyErr_SetString(spoa_error, "No space left available");
		return NULL;
	}
	return Py_None;
}

static PyObject *ps_python_set_var_uint64(PyObject *self, PyObject *args)
{
	const char *name;
	int name_len;
	int scope;
	uint64_t value;

	if (!PyArg_ParseTuple(args, "s#ik", &name, &name_len, &scope, &value))
		return NULL;
	if (!set_var_uint64(worker, name, name_len, scope, value)) {
		PyErr_SetString(spoa_error, "No space left available");
		return NULL;
	}
	return Py_None;
}

static PyObject *ps_python_set_var_ipv4(PyObject *self, PyObject *args)
{
	const char *name;
	int name_len;
	int scope;
	PyObject *ipv4;
	PyObject *value;
	struct in_addr ip;

	if (!PyArg_ParseTuple(args, "s#iO", &name, &name_len, &scope, &ipv4))
		return NULL;
	if (!PyObject_IsInstance(ipv4, ipv4_address)) {
		PyErr_Format(spoa_error, "must be 'IPv4Address', not '%s'", ipv4->ob_type->tp_name);
		return NULL;
	}
	/* Execute packed ... I think .. */
	value = PyObject_GetAttrString(ipv4, "packed");
	if (value == NULL)
		return NULL;
	if (PyString_GET_SIZE(value) != sizeof(ip)) {
		PyErr_Format(spoa_error, "UPv6 manipulation internal error");
		return NULL;
	}
	memcpy(&ip, PyString_AS_STRING(value), PyString_GET_SIZE(value));
	if (!set_var_ipv4(worker, name, name_len, scope, &ip)) {
		PyErr_SetString(spoa_error, "No space left available");
		return NULL;
	}
	return Py_None;
}

static PyObject *ps_python_set_var_ipv6(PyObject *self, PyObject *args)
{
	const char *name;
	int name_len;
	int scope;
	PyObject *ipv6;
	PyObject *value;
	struct in6_addr ip;

	if (!PyArg_ParseTuple(args, "s#iO", &name, &name_len, &scope, &ipv6))
		return NULL;
	if (!PyObject_IsInstance(ipv6, ipv6_address)) {
		PyErr_Format(spoa_error, "must be 'IPv6Address', not '%s'", ipv6->ob_type->tp_name);
		return NULL;
	}
	/* Execute packed ... I think .. */
	value = PyObject_GetAttrString(ipv6, "packed");
	if (value == NULL)
		return NULL;
	if (PyString_GET_SIZE(value) != sizeof(ip)) {
		PyErr_Format(spoa_error, "UPv6 manipulation internal error");
		return NULL;
	}
	memcpy(&ip, PyString_AS_STRING(value), PyString_GET_SIZE(value));
	if (!set_var_ipv6(worker, name, name_len, scope, &ip)) {
		PyErr_SetString(spoa_error, "No space left available");
		return NULL;
	}
	return Py_None;
}

static PyObject *ps_python_set_var_str(PyObject *self, PyObject *args)
{
	const char *name;
	int name_len;
	int scope;
	const char *value;
	int value_len;

	if (!PyArg_ParseTuple(args, "s#is#", &name, &name_len, &scope, &value, &value_len))
		return NULL;
	if (!set_var_string(worker, name, name_len, scope, value, value_len)) {
		PyErr_SetString(spoa_error, "No space left available");
		return NULL;
	}
	return Py_None;
}

static PyObject *ps_python_set_var_bin(PyObject *self, PyObject *args)
{
	const char *name;
	int name_len;
	int scope;
	const char *value;
	int value_len;

	if (!PyArg_ParseTuple(args, "s#is#", &name, &name_len, &scope, &value, &value_len))
		return NULL;
	if (!set_var_bin(worker, name, name_len, scope, value, value_len)) {
		PyErr_SetString(spoa_error, "No space left available");
		return NULL;
	}
	return Py_None;
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

static int ps_python_start_worker(struct worker *w)
{
	PyObject *m;
	PyObject *module_name;
	PyObject *value;
	int ret;

	Py_SetProgramName("spoa-server");
	Py_Initialize();

	module_name = PyString_FromString("ipaddress");
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
		PyErr_Print();
		return 0;
	}

	ipv6_address = PyObject_GetAttrString(module_ipaddress, "IPv6Address");
	if (ipv4_address == NULL) {
		PyErr_Print();
		return 0;
	}

	m = Py_InitModule("spoa", spoa_methods);
	if (m == NULL) {
		PyErr_Print();
		return 0;
	}

	spoa_error = PyErr_NewException("spoa.error", NULL, NULL);
	Py_INCREF(spoa_error);
	PyModule_AddObject(m, "error", spoa_error);


	value = PyLong_FromLong(SPOE_SCOPE_PROC);
	if (value == NULL) {
		PyErr_Print();
		return 0;
	}

	ret = PyModule_AddObject(m, "scope_proc", value);
	if (ret == -1) {
		PyErr_Print();
		return 0;
	}

	value = PyLong_FromLong(SPOE_SCOPE_SESS);
	if (value == NULL) {
		PyErr_Print();
		return 0;
	}

	ret = PyModule_AddObject(m, "scope_sess", value);
	if (ret == -1) {
		PyErr_Print();
		return 0;
	}

	value = PyLong_FromLong(SPOE_SCOPE_TXN);
	if (value == NULL) {
		PyErr_Print();
		return 0;
	}

	ret = PyModule_AddObject(m, "scope_txn", value);
	if (ret == -1) {
		PyErr_Print();
		return 0;
	}

	value = PyLong_FromLong(SPOE_SCOPE_REQ);
	if (value == NULL) {
		PyErr_Print();
		return 0;
	}

	ret = PyModule_AddObject(m, "scope_req", value);
	if (ret == -1) {
		PyErr_Print();
		return 0;
	}

	value = PyLong_FromLong(SPOE_SCOPE_RES);
	if (value == NULL) {
		PyErr_Print();
		return 0;
	}

	ret = PyModule_AddObject(m, "scope_res", value);
	if (ret == -1) {
		PyErr_Print();
		return 0;
	}

	empty_array = PyDict_New();
	if (empty_array == NULL) {
		PyErr_Print();
		return 0;
	}

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
			Py_DECREF(ent);
			PyErr_Print();
			return 0;
		}

		/* Create the name entry */

		key = PyString_FromString("name");
		if (key == NULL) {
			Py_DECREF(kw_args);
			PyErr_Print();
			return 0;
		}

		value = PyString_FromStringAndSize(args[i].name.str, args[i].name.len);
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

		/* Create th value entry */

		key = PyString_FromString("value");
		if (key == NULL) {
			Py_DECREF(kw_args);
			Py_DECREF(ent);
			PyErr_Print();
			return 0;
		}

		switch (args[i].value.type) {
		case SPOE_DATA_T_NULL:
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
				PyErr_Print();
				return 0;
			}
			ip_dict = PyDict_New();
			if (ip_dict == NULL) {
				Py_DECREF(kw_args);
				Py_DECREF(ent);
				Py_DECREF(func);
				PyErr_Print();
				return 0;
			}
			ip_name = PyString_FromString("address");
			if (ip_name == NULL) {
				Py_DECREF(kw_args);
				Py_DECREF(ent);
				Py_DECREF(func);
				Py_DECREF(ip_dict);
				PyErr_Print();
				return 0;
			}
			ip_value = PyUnicode_FromString(ipbuf);
			if (ip_value == NULL) {
				Py_DECREF(kw_args);
				Py_DECREF(ent);
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
				Py_DECREF(ip_dict);
				PyErr_Print();
				return 0;
			}
			value = PyObject_Call(func, empty_array, ip_dict);
			Py_DECREF(func);
			Py_DECREF(ip_dict);
			break;

		case SPOE_DATA_T_STR:
			value = PyString_FromStringAndSize(args[i].value.u.buffer.str, args[i].value.u.buffer.len);
			break;
		case SPOE_DATA_T_BIN:
			value = PyString_FromStringAndSize(args[i].value.u.buffer.str, args[i].value.u.buffer.len);
			break;
		default:
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

	/* Dictionnary { args = <list-of-args> } for the function */

	fkw = PyDict_New();
	if (fkw == NULL) {
		Py_DECREF(kw_args);
		PyErr_Print();
		return 0;
	}

	key = PyString_FromString("args");
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

	result = PyObject_Call(python_ref, empty_array, fkw);
	if (result == NULL) {
		PyErr_Print();
		return 0;
	}

	return 1;
}

__attribute__((constructor))
static void __ps_python_init(void)
{
	ps_register(&ps_python_bindings);
}
