#include "Python.h"
#include <stdio.h>
#include <stdint.h>
#include <string>

#define _(s) ((char *) std::string(s).c_str())

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

void *pydict_get_item_string(void *dict, const char *key)
{
    return PyDict_GetItemString((PyObject *) dict, key);
}

void py_single_int_callback(void *obj, uintptr_t value)
{
    PyObject_CallFunction((PyObject *) obj, _("l"), value);
}

int py_single_int_bool_callback(void *obj, uintptr_t value)
{
    // TODO return the actual return value
    PyObject_CallFunction((PyObject *) obj, _("l"), value);
    return 1;
}

void py_three_int_callback(void *obj, uintptr_t a, uintptr_t b, uintptr_t c)
{
    PyObject_CallFunction((PyObject *) obj, _("lll"), a, b, c);
}

void pyerr_print()
{
    PyErr_Print();
}
