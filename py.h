
void py_init();
void py_fini();
void pyrun_simple_string(const char *s);
void *pystring_from_string(const char *s);
void *pydict_get_item_string(void *dict, const char *key);
void py_single_int_callback(void *obj, uintptr_t value);
int py_single_int_bool_callback(void *obj, uintptr_t value);
void py_three_int_callback(void *obj, uintptr_t a, uintptr_t b, uintptr_t c);
void py_two_obj_one_int_callback(void *obj, void *a, void *b, uintptr_t c);
void pyerr_print();
