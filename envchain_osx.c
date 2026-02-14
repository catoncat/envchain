#include <mach-o/dyld.h>

#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>

#include "envchain.h"

#define ENVCHAIN_SERVICE_PREFIX "envchain-"
#define ENVCHAIN_ITEM_DESCRIPTION "envchain"

SecKeychainRef envchain_keychain = NULL;

typedef struct {
  envchain_search_callback search_callback;
  envchain_namespace_search_callback namespace_callback;
  void *data;
} envchain_search_values_applier_data;

typedef struct {
  envchain_namespace_search_callback callback;
  int head_index;
  char** names;
  void *data;
} envchain_search_namespaces_context;

static void envchain_fail_osstatus(OSStatus status);

int
envchain_set_keychain(const char *target)
{
  OSStatus status;

  if (envchain_keychain != NULL) {
    CFRelease(envchain_keychain);
    envchain_keychain = NULL;
  }

  if (target == NULL || target[0] == '\0') {
    return 0;
  }

  status = SecKeychainOpen(target, &envchain_keychain);
  if (status != noErr) {
    fprintf(stderr, "%s: failed to open keychain `%s`\n", envchain_name, target);
    envchain_fail_osstatus(status);
  }

  return 0;
}

/* misc */

static int
envchain_sortcmp_str(const void *a, const void *b)
{
  return strcmp(*(const char**)a, *(const char**)b);
}

static void
envchain_fail_osstatus(OSStatus status)
{
  CFStringRef str;
  const char *cstr;
  str = SecCopyErrorMessageString(status, NULL);
  cstr = CFStringGetCStringPtr(str, kCFStringEncodingMacRoman);
  if (cstr == NULL) {
    fprintf(stderr, "Error: %d\n", (int)status);
  }
  else {
    fprintf(stderr, "Error: %s\n", cstr);
  }
  CFRelease(str);
  exit(10);
}


static char*
envchain_generate_service_name(const char *name)
{
  char *service_name;
  asprintf(&service_name, "%s%s", ENVCHAIN_SERVICE_PREFIX, name);
  if (service_name == NULL) {
    fprintf(stderr, "Failed to generate service_name\n");
    exit(10);
  }
  return service_name;
}

static CFStringRef
envchain_generate_service_name_cf(const char *name)
{
  return CFStringCreateWithFormat(
      NULL, NULL,
      CFSTR("%s%s"), ENVCHAIN_SERVICE_PREFIX, name
  );
}

static char*
envchain_get_self_exec_path(void)
{
  uint32_t pathlen = 0;
  char *selfpath = malloc(sizeof(char) * 255);
  if (_NSGetExecutablePath(selfpath, &pathlen) < 0) {
    selfpath = realloc(selfpath, sizeof(char) * pathlen);
    if (_NSGetExecutablePath(selfpath, &pathlen) < 0) {
      fprintf(stderr, "NSGetExecutablePath something went wrong :/\n");
      exit(10);
    }
  }

  return selfpath;
}

static char*
envchain_get_real_path(const char *path)
{
  char *selfrealpath = realpath(path, NULL);
  if (selfrealpath == NULL) {
    fprintf(stderr, "Error during retrieve executable path of itself: %s\n", strerror(errno));
    exit(1);
  }

  return selfrealpath;
}

static CFArrayRef
envchain_self_trusted_app_list(void)
{
  char* selfexecpath = envchain_get_self_exec_path();
  char* selfrealpath = envchain_get_real_path(selfexecpath);
  OSStatus status;
  SecTrustedApplicationRef app_exec = NULL;
  SecTrustedApplicationRef app_real = NULL;
  CFMutableArrayRef app_array = NULL;
  CFArrayRef list = NULL;

  app_array = CFArrayCreateMutable(NULL, 0, &kCFTypeArrayCallBacks);
  if (app_array == NULL) {
    fprintf(stderr, "failed to allocate trusted app list\n");
    exit(10);
  }

  status = SecTrustedApplicationCreateFromPath(selfexecpath, &app_exec);
  if (status != noErr) goto fail;
  CFArrayAppendValue(app_array, app_exec);

  if (strcmp(selfexecpath, selfrealpath) != 0) {
    status = SecTrustedApplicationCreateFromPath(selfrealpath, &app_real);
    if (status != noErr) goto fail;
    CFArrayAppendValue(app_array, app_real);
  }

  list = CFArrayCreateCopy(NULL, app_array);

fail:
  if (app_exec != NULL) CFRelease(app_exec);
  if (app_real != NULL) CFRelease(app_real);
  if (app_array != NULL) CFRelease(app_array);
  if (selfexecpath != NULL) free(selfexecpath);
  if (selfrealpath != NULL) free(selfrealpath);
  if (status != noErr) envchain_fail_osstatus(status);

  return list;
}


static void
envchain_search_values_applier(const void *raw_ref, void *raw_context)
{
  OSStatus status;
  envchain_search_values_applier_data *context = (envchain_search_values_applier_data*) raw_context;
  SecKeychainItemRef ref = (SecKeychainItemRef) raw_ref;

  SecKeychainAttribute attr = {kSecAccountItemAttr, 0, NULL};
  if (context->search_callback) {
    attr.tag = kSecAccountItemAttr;
  }
  else {
    attr.tag = kSecServiceItemAttr;
  }
  SecKeychainAttributeList list = {1, &attr};
  SecItemClass klass;
  UInt32 len, keylen = 0;
  char* rawvalue = NULL;
  char* rawkey = NULL;
  char* value = NULL;
  char* key = NULL;

  if (context->search_callback) {
    status = SecKeychainItemCopyContent(
      ref, &klass, &list, &len, (void*)&rawvalue
    );
  }
  else {
    status = SecKeychainItemCopyContent(
      ref, &klass, &list, &len, NULL
    );
  }

  if (status != noErr) goto fail;

  for(UInt32 i = 0; i < list.count; i++) {
    SecKeychainAttribute attr = list.attr[i];
    if (attr.tag == kSecAccountItemAttr || attr.tag == kSecServiceItemAttr) {
      rawkey = (char*)attr.data;
      keylen = attr.length;

      key = malloc(keylen+1);
      if (key == NULL) goto fail;

      memcpy(key, rawkey, keylen);
      key[keylen] = '\0';

      if (attr.tag == kSecServiceItemAttr) {
        if (strncmp(key, ENVCHAIN_SERVICE_PREFIX, strlen(ENVCHAIN_SERVICE_PREFIX)) == 0) {
          keylen = keylen - strlen(ENVCHAIN_SERVICE_PREFIX);
          char* service_name = malloc(keylen + 1);

          memcpy(service_name, &key[strlen(ENVCHAIN_SERVICE_PREFIX)], keylen);
          service_name[keylen] = '\0';

          free(key);
          key = service_name;
        }
      }
      break;
    }
  }

  if (rawkey == NULL) {
    fprintf(stderr, "Can't find account name\n");
    goto ensure;
  }

  if (context->search_callback) {
    value = malloc(len+1);
    if (value == NULL) goto fail;
    memcpy(value,rawvalue,len);
    value[len] = '\0';
    context->search_callback(key, value, context->data);
  }
  else {
    context->namespace_callback(key, context->data);
  }

  goto ensure;
fail:
  fprintf(stderr, "Something wrong during searching value\n");
  if (errno) fprintf(stderr, "errno: %s\n", strerror(errno));
ensure:
  if (value) {
    memset(value, 0, len);
    free(value);
  }
  if (key) {
    memset(key, 0, keylen);
    free(key);
  }
  if (context->search_callback) {
    SecKeychainItemFreeContent(&list, rawvalue);
  }
  return;
}

static void
envchain_search_namespaces_uniqufier(const char* name, void *raw_context)
{
  envchain_search_namespaces_context* context = (envchain_search_namespaces_context*)raw_context;

  char* item = malloc((strlen(name) * sizeof(char)) + 1);
  strcpy(item, name);

  context->names[context->head_index] = item;
  context->head_index++;
}

int
envchain_search_namespaces(envchain_namespace_search_callback callback, void *data)
{
  OSStatus status;
  int result = 0;
  CFArrayRef items = NULL;
  CFStringRef description = CFStringCreateWithCString(NULL, ENVCHAIN_ITEM_DESCRIPTION, kCFStringEncodingUTF8);
  CFArrayRef search_list = NULL;
  CFMutableDictionaryRef query = NULL;

  query = CFDictionaryCreateMutable(
      kCFAllocatorDefault, 0,
      &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
  CFDictionarySetValue(query, kSecClass, kSecClassGenericPassword);
  CFDictionarySetValue(query, kSecAttrDescription, description);
  CFDictionarySetValue(query, kSecReturnRef, kCFBooleanTrue);
  CFDictionarySetValue(query, kSecMatchLimit, kSecMatchLimitAll);

  if (envchain_keychain != NULL) {
    const void *search_vals[] = {envchain_keychain};
    search_list = CFArrayCreate(
      NULL, search_vals, 1, &kCFTypeArrayCallBacks
    );
    CFDictionarySetValue(query, kSecMatchSearchList, search_list);
  }

  status = SecItemCopyMatching(query, (CFTypeRef *)&items);
  if (status != errSecItemNotFound && status != noErr) goto fail;

  if (status == errSecItemNotFound || CFArrayGetCount(items) == 0) {
    goto fail;
  }
  
  char** names = malloc(sizeof(char*) * CFArrayGetCount(items));
  if (names == NULL) {
    fprintf(stderr, "malloc fail (names)\n");
    goto fail;
  }

  envchain_search_namespaces_context context = {callback, 0, names, data};
  envchain_search_values_applier_data applier_context = {NULL, envchain_search_namespaces_uniqufier, &context};
  CFArrayApplyFunction(
    items, CFRangeMake(0, CFArrayGetCount(items)),
    &envchain_search_values_applier, &applier_context
  );

  qsort(names, CFArrayGetCount(items), sizeof(char*), envchain_sortcmp_str);
  char *prev_name = NULL;
  for(int i = 0; i < CFArrayGetCount(items); i++) {
    if (!prev_name || strcmp(prev_name, names[i]) != 0)
      callback(names[i], data);
    prev_name = names[i];
  }
  for(int i = 0; i < CFArrayGetCount(items); i++) free(names[i]);

  free(names);

fail:
  if (items != NULL) CFRelease(items);
  if (search_list != NULL) CFRelease(search_list);
  if (query != NULL) CFRelease(query);
  if (description != NULL) CFRelease(description);
  if (status != noErr && status != errSecItemNotFound) envchain_fail_osstatus(status);

  return result;
}

int
envchain_search_values(const char *name, envchain_search_callback callback, void *data)
{
  OSStatus status;
  int result = 0;
  CFStringRef service_name = envchain_generate_service_name_cf(name);
  CFArrayRef items = NULL;
  CFArrayRef search_list = NULL;
  CFMutableDictionaryRef query = NULL;

  query = CFDictionaryCreateMutable(
      kCFAllocatorDefault, 0,
      &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
  CFDictionarySetValue(query, kSecClass, kSecClassGenericPassword);
  CFDictionarySetValue(query, kSecAttrService, service_name);
  CFDictionarySetValue(query, kSecReturnRef, kCFBooleanTrue);
  CFDictionarySetValue(query, kSecMatchLimit, kSecMatchLimitAll);

  if (envchain_keychain != NULL) {
    const void *search_vals[] = {envchain_keychain};
    search_list = CFArrayCreate(
      NULL, search_vals, 1, &kCFTypeArrayCallBacks
    );
    CFDictionarySetValue(query, kSecMatchSearchList, search_list);
  }

  status = SecItemCopyMatching(query, (CFTypeRef *)&items);
  if (status != errSecItemNotFound && status != noErr) goto fail;

  if (status == errSecItemNotFound || CFArrayGetCount(items) == 0) {
    fprintf(stderr,
      "WARNING: namespace `%s` not defined.\n"
      "         You can set via running `%s --set %s SOME_ENV_NAME`.\n\n",
      name, envchain_name, name
    );
    result = 1;
    goto fail;
  }
  
  envchain_search_values_applier_data context = {callback, NULL, data};
  CFArrayApplyFunction(
    items, CFRangeMake(0, CFArrayGetCount(items)),
    &envchain_search_values_applier, &context
  );

fail:
  if (items != NULL) CFRelease(items);
  if (search_list != NULL) CFRelease(search_list);
  if (query != NULL) CFRelease(query);
  if (service_name != NULL) CFRelease(service_name);
  if (status != noErr && status != errSecItemNotFound) envchain_fail_osstatus(status);

  return result;
}

static int
envchain_find_value(const char *name, const char *key, SecKeychainItemRef *ref)
{
  OSStatus status;
  char *service_name = envchain_generate_service_name(name);

  status = SecKeychainFindGenericPassword(
    envchain_keychain,
    strlen(service_name), service_name,
    strlen(key), key,
    NULL, NULL,
    ref
  );

  free(service_name);

  if (status != noErr && status != errSecItemNotFound) {
    if (ref != NULL) CFRelease(ref);
    envchain_fail_osstatus(status);
  }

  return status == errSecItemNotFound ? 0 : 1;
}

static int
envchain_apply_item_access(SecKeychainItemRef ref, int require_passphrase)
{
  OSStatus status = noErr;
  SecAccessRef access_ref = NULL;
  CFArrayRef acl_list = NULL;
  CFArrayRef app_list = NULL;
  CFStringRef desc = NULL;

  status = SecKeychainItemCopyAccess(ref, &access_ref);
  if (status != noErr) goto fail;

  acl_list = SecAccessCopyMatchingACLList(
    access_ref, kSecACLAuthorizationDecrypt
  );
  SecACLRef acl = (SecACLRef)CFArrayGetValueAtIndex(acl_list, 0);

  if (acl == NULL) {
    fprintf(stderr, "error: There's no ACL?\n");
    status = -1;
    goto fail;
  }

  SecKeychainPromptSelector prompt;
  status = SecACLCopyContents(acl, &app_list, &desc, &prompt);
  if (status != noErr) goto fail;
  if (app_list != NULL) {
    CFRelease(app_list);
    app_list = NULL;
  }

  if(require_passphrase == 1) {
    if (prompt == 0) prompt = 0x100;
    prompt |= kSecKeychainPromptRequirePassphase;
    app_list = CFArrayCreate(NULL, NULL, 0, &kCFTypeArrayCallBacks);
  }
  else {
    prompt = 0;
    app_list = envchain_self_trusted_app_list();
  }

  status = SecACLSetContents(acl, app_list, desc, prompt);
  if (status != noErr) goto fail;

  status = SecKeychainItemSetAccess(ref, access_ref);

fail:
  if (app_list != NULL) CFRelease(app_list);
  if (desc != NULL) CFRelease(desc);
  if (access_ref != NULL) CFRelease(access_ref);
  if (acl_list != NULL) CFRelease(acl_list);
  if (status != noErr) envchain_fail_osstatus(status);
  return 0;
}

void
envchain_save_value(const char *name, const char *key, char *value, int require_passphrase)
{
  char *service_name = envchain_generate_service_name(name);
  OSStatus status;
  SecKeychainItemRef ref = NULL;

  if (envchain_find_value(name, key, &ref) == 0) {
    status = SecKeychainAddGenericPassword(
      envchain_keychain,
      strlen(service_name), service_name,
      strlen(key), key,
      strlen(value), value,
      &ref
    );
  }
  else {
    status = SecKeychainItemModifyAttributesAndData(
      ref,
      NULL,
      strlen(value), value
    );
  }

  free(service_name);

  if (status != noErr) goto fail;

  /* Set description */
  SecKeychainAttribute attr_desc = {
    kSecDescriptionItemAttr, strlen(ENVCHAIN_ITEM_DESCRIPTION), ENVCHAIN_ITEM_DESCRIPTION};
  SecKeychainAttributeList attrs = {1, &attr_desc};
  status = SecKeychainItemModifyAttributesAndData(
    ref,
    &attrs,
    strlen(value), value
  );

  if (status != noErr) goto fail;

  if (require_passphrase >= 0) {
    envchain_apply_item_access(ref, require_passphrase);
  }

fail:
  if (ref != NULL) { CFRelease(ref); }
  if (status != noErr) envchain_fail_osstatus(status);

  return;
}

int
envchain_update_value_access(const char *name, const char *key, int require_passphrase)
{
  SecKeychainItemRef ref = NULL;

  if (require_passphrase < 0) {
    fprintf(stderr, "require_passphrase must be 0 or 1\n");
    return 1;
  }

  if (envchain_find_value(name, key, &ref) == 0) {
    fprintf(stderr, "WARNING: key `%s.%s` not found\n", name, key);
    return 1;
  }

  envchain_apply_item_access(ref, require_passphrase);

  if (ref != NULL) {
    CFRelease(ref);
  }
  return 0;
}

void
envchain_delete_value(const char *name, const char *key) {
  SecKeychainItemRef ref = NULL;
  if (envchain_find_value(name, key, &ref) != 0) {
    SecKeychainItemDelete(ref);
  }
}
