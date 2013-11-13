#include <stdio.h>
#include <stdint.h>
#include "Python.h"

void py_init()
{
    Py_Initialize();
}

void py_fini()
{
    Py_Finalize();
}

void pyrun_simple_string(const char *s)
{
    PyRun_SimpleString(s);
}

void *pystring_from_string(const char *s)
{
    return PyString_FromString(s);
}

void *pydict_get_item(void *dict, void *key)
{
    return PyDict_GetItem((PyObject *) dict, (PyObject *) key);
}

void py_single_int_callback(void *obj, uintptr_t value)
{
    PyObject_CallFunction((PyObject *) obj, "l", value);
}

int py_single_int_bool_callback(void *obj, uint32_t value)
{
    // TODO return the actual return value
    PyObject_CallFunction((PyObject *) obj, "l", value);
    return 1;
}

void py_three_int_callback(void *obj, uintptr_t a, uintptr_t b, uintptr_t c)
{
    PyObject_CallFunction((PyObject *) obj, "lll", a, b, c);
}
