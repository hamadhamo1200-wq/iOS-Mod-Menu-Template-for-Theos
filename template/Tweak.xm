#import <substrate.h>
#import <mach-o/dyld.h>
#import <dlfcn.h>
#import <sys/sysctl.h>
#import <sys/stat.h>
#import <Foundation/Foundation.h>

// 1. درع التخفي لمنع اكتشاف الحقن والمراقبة
static int (*orig_sysctl)(int *name, u_int namelen, void *oldp, size_t *oldlenp, void *newp, size_t newlen);
int custom_sysctl(int *name, u_int namelen, void *oldp, size_t *oldlenp, void *newp, size_t newlen) {
    int ret = orig_sysctl(name, namelen, oldp, oldlenp, newp, newlen);
    if (name[0] == CTL_KERN && name[1] == KERN_PROC && name[2] == KERN_PROC_PID) {
        struct kinfo_proc *info = (struct kinfo_proc *)oldp;
        if (info && (info->kp_proc.p_flag & P_TRACED)) {
            info->kp_proc.p_flag ^= P_TRACED; // تعمية الرادار
        }
    }
    return ret;
}

// 2. إخفاء ملفات الهاك وتطبيق ESign من فحص اللعبة
static int (*orig_stat)(const char *restrict path, struct stat *restrict buf);
int custom_stat(const char *restrict path, struct stat *restrict buf) {
    NSString *pathStr = [NSString stringWithUTF8String:path];
    if ([pathStr containsString:@"ESign"] || 
        [pathStr containsString:@"dylib"] || 
        [pathStr containsString:@"MobileSubstrate"] ||
        [pathStr containsString:@"ShadowTrackerExtra"]) {
        return -1; // إخبار اللعبة أن الملف غير موجود (خدعة 404)
    }
    return orig_stat(path, buf);
}

// 3. تعطيل دوال الحماية وإرسال التقارير للسيرفر
void* (*orig_dlsym)(void* handle, const char* symbol);
void* custom_dlsym(void* handle, const char* symbol) {
    // تعطيل أقوى أنظمة الفحص
    if (strcmp(symbol, "TssSDKInit") == 0 || 
        strcmp(symbol, "CheckIntegrity") == 0 || 
        strcmp(symbol, "ReportCheatData") == 0 ||
        strcmp(symbol, "tersafe_init") == 0) {
        return NULL; // إيقاف عمل الدالة تماماً
    }
    return orig_dlsym(handle, symbol);
}

// تشغيل الدرع الثلاثي الأبعاد فور فتح اللعبة
%ctor {
    NSLog("[The Architect] Ultimate Shield Activated...");
    MSHookFunction((void *)sysctl, (void *)custom_sysctl, (void **)&orig_sysctl);
    MSHookFunction((void *)stat, (void *)custom_stat, (void **)&orig_stat);
    MSHookFunction((void *)dlsym, (void *)custom_dlsym, (void **)&orig_dlsym);
}
// Boruto
