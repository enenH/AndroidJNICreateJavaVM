#include <cstdio>
#include <cstdlib>
#include <dlfcn.h>
#include <android/log.h>
#include <jni.h>
#include <pthread.h>
#include <unistd.h>
#include <sys/mman.h>

#include "dobby.h"

/*https://blog.quarkslab.com/android-greybox-fuzzing-with-afl-frida-mode.html*/

/* JniInvocationImpl struct (from libnativehelper/JniInvocation.c) */
typedef struct JniInvocation {
    const char* jni_provider_library_name;
    void* jni_provider_library;

    jint (*JNI_GetDefaultJavaVMInitArgs)(void*);

    jint (*JNI_CreateJavaVM)(JavaVM**, JNIEnv**, void*);

    jint (*JNI_GetCreatedJavaVMs)(JavaVM**, jsize, jsize*);
} JniInvocationImpl;

/* CTX */
typedef struct JavaContext {
    JavaVM* vm;
    JNIEnv* env;
    JniInvocationImpl* invoc;
} JavaCTX;

static JavaCTX ctx;

#define ANDROID_RUNTIME_DSO "libandroid_runtime.so"

typedef jint (*JNI_CreateJavaVM_t)(JavaVM** p_vm, JNIEnv** p_env, void* vm_args);

typedef void (*JniInvocation_ctor_t)(void*);

typedef void (*JniInvocation_dtor_t)(void*);

typedef void (*JniInvocation_Init_t)(void*, const char*);

static void modify_function(void* func) {
    unsigned long page_start = (unsigned long)func & ~(PAGE_SIZE - 1);
    if (mprotect((void*)page_start, PAGE_SIZE, PROT_READ | PROT_WRITE | PROT_EXEC) == -1) {
        return;
    }
    unsigned char* p = (unsigned char*)func;
    //RET
    p[0] = 0xC0;
    p[1] = 0x03;
    p[2] = 0x5F;
    p[3] = 0xD6;
    // mprotect((void *) page_start, PAGE_SIZE, PROT_READ | PROT_EXEC);
}


struct startup {
    void*(*start_routine)(void*);

    void* arg;
};

void* my_start_routine(void* arg) {
    startup* up = (startup*)arg;

    // char thread_name[16]{0};
    //  pthread_getname_np(pthread_self(), thread_name, sizeof(thread_name));
    // LOGD("thread name %s %d", thread_name,gettid());
    //if (strstr(thread_name, "binder:")|| strstr(thread_name,"main")){
    while (!ctx.vm) {
        usleep(1000);
    }
    JNIEnv* Env;
    for (int i = 0; i < 10; ++i) {
        if (ctx.vm->AttachCurrentThread(&Env, nullptr) == JNI_OK) {
            break;
        }
    }
    // LOGD("hooked thread %s %d", thread_name,gettid());
    // }
    return up->start_routine(up->arg);
}

static int (*real_pthread_create)(pthread_t*, const pthread_attr_t*, void*(*)(void*), void*) = NULL;


int pthread_create_hook(pthread_t* thread, const pthread_attr_t* attr, void*(*start_routine)(void*), void* arg) {
    startup* up = (startup*)malloc(sizeof(*up));
    up->start_routine = start_routine;
    up->arg = arg;

    return real_pthread_create(thread, attr, my_start_routine, up);
}

/* API */
JavaCTX* init_java_env(char** jvm_options, uint8_t jvm_nb_options) {
    JNI_CreateJavaVM_t JNI_CreateJVM;
    JniInvocationImpl*(*JniInvocationCreate)();
    bool (*JniInvocationInit)(JniInvocationImpl*, const char*);
    jint (*registerFrameworkNatives)(JNIEnv*);
    void* runtime_dso;

    JniInvocation_ctor_t JniInvocation_ctor;
    //JniInvocation_dtor_t JniInvocation_dtor;
    JniInvocation_Init_t JniInvocation_Init;

    if ((runtime_dso = dlopen(ANDROID_RUNTIME_DSO, RTLD_NOW)) == NULL) {
        printf("[!] %s\n", dlerror());
        return nullptr;
    }

    JNI_CreateJVM = (JNI_CreateJavaVM_t)dlsym(runtime_dso, "JNI_CreateJavaVM");
    if (!JNI_CreateJVM) {
        printf("Cannot find JNI_CreateJavaVM\n");
        return nullptr;
    }

    registerFrameworkNatives = (jint (*)(JNIEnv*))dlsym(runtime_dso, "registerFrameworkNatives");
    if (!registerFrameworkNatives) {
        registerFrameworkNatives = (jint (*)(JNIEnv*))dlsym(runtime_dso,
                                                            "Java_com_android_internal_util_WithFramework_registerNatives");
        if (!registerFrameworkNatives) {
            printf("Cannot find registerFrameworkNatives\n");
            return nullptr;
        }
    }

    JniInvocationCreate = (JniInvocationImpl *(*)())dlsym(runtime_dso, "JniInvocationCreate");
    JniInvocationInit = (bool (*)(JniInvocationImpl*, const char*))dlsym(runtime_dso, "JniInvocationInit");
    if (JniInvocationCreate && JniInvocationInit) {
        ctx.invoc = JniInvocationCreate();
        JniInvocationInit(ctx.invoc, ANDROID_RUNTIME_DSO);
    } else {
        JniInvocation_ctor = (JniInvocation_ctor_t)dlsym(runtime_dso, "_ZN13JniInvocationC1Ev");
        JniInvocation_Init = (JniInvocation_Init_t)dlsym(runtime_dso, "_ZN13JniInvocation4InitEPKc");

        if (!JniInvocation_ctor || !JniInvocation_Init) {
            printf("Cannot find JniInvocationImpl\n");
            return nullptr;
        }

        ctx.invoc = (JniInvocationImpl*)calloc(1, 256);
        JniInvocation_ctor(ctx.invoc);
        JniInvocation_Init(ctx.invoc, NULL);
    }

    JavaVMOption options[jvm_nb_options];
    JavaVMInitArgs args;
    args.version = JNI_VERSION_1_6;
    if (jvm_nb_options > 0) {
        for (int i = 0; i < jvm_nb_options; ++i)
            options[i].optionString = jvm_options[i];

        args.nOptions = jvm_nb_options;
        args.options = options;
    } else {
        args.nOptions = 0;
        args.options = NULL;
    }

    args.ignoreUnrecognized = JNI_TRUE;

    int api_level = android_get_device_api_level();
    if (api_level < 31) {
        const char* symbols[] = {
            "InitializeSignalChain",
            "ClaimSignalChain",
            "UnclaimSignalChain",
            "InvokeUserSignalHandler",
            "EnsureFrontOfChain",
            "AddSpecialSignalHandlerFn",
            "RemoveSpecialSignalHandlerFn",
            NULL
        };
        for (const char** sym = symbols; *sym; ++sym) {
            void* func = DobbySymbolResolver("libsigchain.so", *sym);
            if (!func) {
                // fprintf(stderr, "%s\n", dlerror());
                continue;
            }
            modify_function(func);
        }
    }

    jint status = JNI_CreateJVM(&ctx.vm, &ctx.env, &args);
    if (status == JNI_ERR) return nullptr;

    printf("[d] vm: %p, env: %p\n", ctx.vm, ctx.env);

    status = registerFrameworkNatives(ctx.env);
    if (status == JNI_ERR) return nullptr;

    DobbyHook((void*)pthread_create, (void*)pthread_create_hook, (void**)&real_pthread_create);
    return &ctx;
}

static void JavaEnvDestructor(void*) {
    ctx.vm->DetachCurrentThread();
}

static JNIEnv* GetJavaEnv() {
    static uint32_t TlsSlot = 0;
    if (TlsSlot == 0) {
        pthread_key_create((pthread_key_t*)&TlsSlot, &JavaEnvDestructor);
    }
    auto* Env = (JNIEnv*)pthread_getspecific(TlsSlot);
    if (Env == nullptr) {
        ctx.vm->GetEnv((void**)&Env, JNI_VERSION_1_6);
        jint AttachResult = ctx.vm->AttachCurrentThread(&Env, nullptr);
        if (AttachResult == JNI_ERR) {
            return nullptr;
        }
        pthread_setspecific(TlsSlot, Env);
    }
    return Env;
}

int main() {
    init_java_env(nullptr, 0);
    if (!ctx.vm) {
        printf("Failed to initialize Java environment\n");
        return -1;
    }

    //System.out.println("Hello, World!");

    auto env = GetJavaEnv();
    if (env == nullptr) {
        printf("Failed to get JNIEnv\n");
        return -1;
    }

    // Find the System class
    jclass systemClass = env->FindClass("java/lang/System");
    if (systemClass == nullptr) {
        printf("Failed to find the System class\n");
        return -1;
    }

    // Find the PrintStream class
    jclass printStreamClass = env->FindClass("java/io/PrintStream");
    if (printStreamClass == nullptr) {
        printf("Failed to find the PrintStream class\n");
        return -1;
    }

    // Get the System.out field, which is a static field
    jfieldID outField = env->GetStaticFieldID(systemClass, "out", "Ljava/io/PrintStream;");
    if (outField == nullptr) {
        printf("Failed to get the out field\n");
        return -1;
    }

    // Get the PrintStream.println method
    jmethodID printlnMethod = env->GetMethodID(printStreamClass, "println", "(Ljava/lang/String;)V");
    if (printlnMethod == nullptr) {
        printf("Failed to get the println method\n");
        return -1;
    }

    // Get the System.out object
    jobject outObject = env->GetStaticObjectField(systemClass, outField);
    if (outObject == nullptr) {
        printf("Failed to get the out object\n");
        return -1;
    }

    // Create a string
    jstring helloWorldString = env->NewStringUTF("Hello, World!");

    // Call the println method
    env->CallVoidMethod(outObject, printlnMethod, helloWorldString);

    return 0;
}
