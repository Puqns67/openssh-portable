#include <grp.h>
#include <netdb.h>
#include <stdbool.h>
#include <unistd.h>

#include <libnotify/notify.h>

#include "hostfile.h"
#include "log.h"
#include "misc.h"
#include "pathnames.h"
#include "servconf.h"
#include "sshkey.h"
#include "xmalloc.h"

#include "auth.h"
#include "channels.h"
#include "session.h"

#include "toml-c.h"

typedef struct NotifySettings {
  bool loaded;
  char *source;
  char *title;
  char *icon;
  char *content;
} NotifySettings;

typedef struct NotifyUserSettings {
  bool loaded;
  char *fingerprint;
  char *name;
  char *extra_motd;
  bool do_notify;
  char *notify_title;
  char *notify_icon;
  char *notify_content;
} NotifyUser;

extern ServerOptions options;

struct NotifySettings settings;
struct NotifyUserSettings usersettings;

char *toml_table_string_safe(const toml_table_t *tbl, const char *key,
                             char *def) {
  toml_value_t v = toml_table_string(tbl, key);
  if (v.ok)
    return v.u.s;
  return def;
}

bool toml_table_bool_safe(const toml_table_t *tbl, const char *key, bool def) {
  toml_value_t v = toml_table_bool(tbl, key);
  if (v.ok)
    return v.u.b;
  return def;
}

void do_notify(const char *msg, const char *title, const char *icon) {
  char *socket_path = NULL;
  xasprintf(&socket_path, "unix:path=/run/user/%d/bus", getuid());
  setenv("DBUS_SESSION_BUS_ADDRESS", socket_path, 0);

  if (!notify_init(settings.source)) {
    error("Cannot init libnotify");
    return;
  }

  {
    char *server_name = NULL;
    char *server_vendor = NULL;
    char *server_version = NULL;
    char *server_spec_version = NULL;

    notify_get_server_info(&server_name, &server_vendor, &server_version,
                           &server_spec_version);

    debug("Notify: Server name: %s, Server vendor: %s, Server version: %s, "
          "Server spec version: %s",
          server_name, server_vendor, server_version, server_spec_version);
  }

  NotifyNotification *notification =
      notify_notification_new(title == NULL ? settings.title : title, msg,
                              icon == NULL ? settings.icon : icon);

  notify_notification_set_urgency(notification, NOTIFY_URGENCY_CRITICAL);

  if (!notify_notification_show(notification, NULL))
    error("Cannot send notify with libnotify");

  g_object_unref(G_OBJECT(notification));
  notify_uninit();
}

void load_notify_config(const Session *s) {
  if (settings.loaded)
    return;

  usersettings.fingerprint = sshkey_fingerprint(
      s->authctxt->auth_method_key, options.fingerprint_hash, SSH_FP_DEFAULT);
  usersettings.do_notify = true;

  // get config file
  char *config_path = NULL;
  xasprintf(&config_path, "%s/%s/notify.toml", s->pw->pw_dir,
            _PATH_SSH_USER_DIR);

  // open config file
  FILE *fp = fopen(config_path, "r");
  if (!fp) {
    fprintf(stderr, "Warning: unable to open config file");
    return;
  }

  // parse config file
  char errbuf[512];
  toml_table_t *config = toml_parse_file(fp, errbuf, sizeof(errbuf));
  if (!config) {
    fprintf(stderr, "Error: unable to parse config file: %s\n", errbuf);
    return;
  }

  // get global settings
  toml_table_t *settings_config = toml_table_table(config, "settings");
  settings.source =
      toml_table_string_safe(settings_config, "source", "sshd-session");
  settings.title =
      toml_table_string_safe(settings_config, "title", "反视奸小助手");
  settings.icon =
      toml_table_string_safe(settings_config, "icon", "dialog-information");
  settings.content =
      toml_table_string_safe(settings_config, "content", "有人视奸喵！");

  settings.loaded = true;

  // get notify config for current fingerprint
  toml_table_t *user_config = NULL;
  toml_array_t *users = toml_table_array(config, "user");
  int xl = toml_array_len(users);
  for (int x = 0; x < xl; x++) {
    user_config = toml_array_table(users, x);
    toml_array_t *fingerprints = toml_table_array(user_config, "fingerprint");
    int yl = toml_array_len(fingerprints);
    for (int y = 0; y < yl; y++) {
      toml_value_t fingerprint = toml_array_string(fingerprints, y);
      if (fingerprint.ok &&
          strcmp(fingerprint.u.s, usersettings.fingerprint) == 0)
        goto notify_fingerprint_matched;
    }
  }

  return;

notify_fingerprint_matched:
  // get extra parameter
  usersettings.name = toml_table_string_safe(user_config, "name", NULL);
  usersettings.extra_motd =
      toml_table_string_safe(user_config, "extra_motd", NULL);
  usersettings.do_notify = toml_table_bool_safe(user_config, "do_notify", true);
  usersettings.notify_title =
      toml_table_string_safe(user_config, "notify_title", NULL);
  usersettings.notify_icon =
      toml_table_string_safe(user_config, "notify_icon", NULL);
  usersettings.notify_content =
      toml_table_string_safe(user_config, "notify_content", NULL);

  usersettings.loaded = true;
}

void do_login_notify(const Session *s, const char *command) {
  load_notify_config(s);
  if (!settings.loaded)
    return;

  if (usersettings.loaded && !usersettings.do_notify)
    return;

  char *msg = settings.content;
  if (usersettings.loaded && usersettings.notify_content != NULL)
    msg = usersettings.notify_content;

  if (usersettings.loaded && usersettings.name != NULL)
    xasprintf(&msg, "%s\n公钥所有者：%s", msg, usersettings.name);
  else
    xasprintf(&msg, "%s\n公钥指纹：%s", msg, usersettings.fingerprint);

  if (command != NULL)
    xasprintf(&msg, "%s\n执行命令：\n%s", msg, command);

  if (usersettings.loaded)
    do_notify(msg, usersettings.notify_title, usersettings.notify_icon);
  else
    do_notify(msg, NULL, NULL);
}

void do_extra_motd(const Session *s) {
  load_notify_config(s);
  if (!settings.loaded)
    return;
  if (usersettings.loaded && usersettings.extra_motd != NULL)
    printf("%s\n", usersettings.extra_motd);
}
