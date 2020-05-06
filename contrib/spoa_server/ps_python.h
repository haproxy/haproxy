/* ps_python.h: SPOA Python processing includes
 *
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

#ifndef __PS_PYTHON_H__
#define __PS_PYTHON_H__

#include <Python.h>

#if PY_MAJOR_VERSION >= 3
	#define IS_PYTHON_3K 1
	#define IS_PYTHON_27 0
#elif PY_MAJOR_VERSION == 2 && PY_MINOR_VERSION == 7
	#define IS_PYTHON_3K 0
	#define IS_PYTHON_27 1
#else
	#error "Unsupported Python Version - Please use Python 3"
#endif /* PY_MAJOR_VERSION */

#if IS_PYTHON_3K
	#define PY_INIT_MODULE(instance, name, methods, moduledef) \
		(instance = PyModule_Create(moduledef))
	#define PY_STRING_FROM_STRING PyUnicode_FromString
	#define PY_STRING_FROM_STRING_AND_SIZE PyUnicode_FromStringAndSize
	#define PY_BYTES_FROM_STRING_AND_SIZE PyBytes_FromStringAndSize
	#define PY_STRING_GET_SIZE PyBytes_Size
	#define PY_STRING_AS_STRING PyBytes_AsString
#elif IS_PYTHON_27
	#define PY_INIT_MODULE(instance, name, methods, moduledef) \
		(instance = Py_InitModule(name, methods))
	#define PY_STRING_FROM_STRING PyString_FromString
	#define PY_STRING_FROM_STRING_AND_SIZE PyString_FromStringAndSize
	#define PY_BYTES_FROM_STRING_AND_SIZE PyString_FromStringAndSize
	#define PY_STRING_GET_SIZE PyString_GET_SIZE
	#define PY_STRING_AS_STRING PyString_AS_STRING
#endif /* IS_PYTHON_3K */

#endif /* __PS_PYTHON_H__ */

/* EOF */
