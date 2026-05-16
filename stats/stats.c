#include <Python.h>
#include "stats.h"
#include <stdio.h>

PyObject *pModule;
PyObject *pFunc;

PyThreadState *main_ts;

void init_python_environment(){
    Py_Initialize();

    PyRun_SimpleString("import sys");
    PyRun_SimpleString("sys.path.append('../../stats')");

    PyObject *pName = PyUnicode_DecodeFSDefault("analyzer");
    pModule = PyImport_Import(pName);
    Py_DECREF(pName);

    if(pModule != NULL){
        pFunc = PyObject_GetAttrString(pModule, "run_statistical_analysis");
        if(!pFunc || !PyCallable_Check(pFunc)){
            if(PyErr_Occurred()){
                PyErr_Print();
            }
            fprintf(stderr, "Cannot find function 'run_statistical_analysis'! \n");
        }
    }else{
        PyErr_Print();
        fprintf(stderr, "Failed to load 'analyzer'module! \n");
    }

    main_ts = PyEval_SaveThread();
;
}


void close_python_environment(){
    PyEval_RestoreThread(main_ts);
    //PyGILState_Ensure();
    Py_XDECREF(pFunc);
    Py_XDECREF(pModule);
    Py_Finalize();
}


static int call_python_analyzer(int64_t *meas_matrix, int num_rows){
    int guessed_byte = -1;

    PyGILState_STATE gstate = PyGILState_Ensure();

    if(pFunc && PyCallable_Check(pFunc)){

        Py_ssize_t byte_size = num_rows * L_SIZE * sizeof(int64_t);

        PyObject *pMemoryView = PyMemoryView_FromMemory((char *)meas_matrix, byte_size, PyBUF_READ);

        PyObject *pArgs = PyTuple_New(3);
        PyTuple_SetItem(pArgs, 0, pMemoryView);
        PyTuple_SetItem(pArgs, 1 , PyLong_FromLong(num_rows));
        PyTuple_SetItem(pArgs, 2, PyLong_FromLong(L_SIZE));

        PyObject *pValue = PyObject_CallObject(pFunc, pArgs);
        Py_DECREF(pArgs);

        if(pValue != NULL){
            guessed_byte = (int)PyLong_AsLong(pValue);
            Py_DECREF(pValue);
        }else{
            PyErr_Print();
            fprintf(stderr, "Call to 'run_statistical_analysis()' failed! \n");
        }

    }

    PyGILState_Release(gstate);

    return guessed_byte;
}

//function called in do_attack_thread to analyze the measurements of a single byte
int analyze_single_byte(struct attack_result *result){
    return call_python_analyzer((int64_t *)result->time_meas, 256);
}

//function called in do_attack_thread to analyze the measurements of the double bytes attack (first attack)
int analyze_double_bytes(struct first_attack_result *result){
    return call_python_analyzer((int64_t *)result->time_meas, 65536);
}