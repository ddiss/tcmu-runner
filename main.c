/*
 * Copyright 2014, Red Hat, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may
 * not use this file except in compliance with the License. You may obtain
 * a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
*/

/*
 * A daemon that ties handler modules together with TCMU devices exported via
 * UIO. It listens for device change notifications via netlink, and handles the
 * messy parts of the TCMU command ring so the handlers don't have to.
 */

#define _GNU_SOURCE
#define _BITS_UIO_H
#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#include <errno.h>
#include <dirent.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <assert.h>
#include <dlfcn.h>
#include <pthread.h>
#include <signal.h>
#include <glib.h>
#include <gio/gio.h>

#include <libnl3/netlink/genl/genl.h>
#include <libnl3/netlink/genl/mngt.h>
#include <libnl3/netlink/genl/ctrl.h>
#include <linux/target_core_user.h>
#include "darray.h"
#include "tcmu-runner.h"

#define ARRAY_SIZE(X) (sizeof(X) / sizeof((X)[0]))

#define HANDLER_PATH "."

darray(struct tcmu_handler) handlers = darray_new();

struct tcmu_thread {
	pthread_t thread_id;
	char dev_name[16]; /* e.g. "uio14" */
};

static darray(struct tcmu_thread) threads = darray_new();

static struct nla_policy tcmu_attr_policy[TCMU_ATTR_MAX+1] = {
	[TCMU_ATTR_DEVICE]	= { .type = NLA_STRING },
	[TCMU_ATTR_MINOR]	= { .type = NLA_U32 },
};

static int add_device(char *dev_name, char *cfgstring);
static void remove_device(char *dev_name, char *cfgstring);

static int handle_netlink(struct nl_cache_ops *unused, struct genl_cmd *cmd,
			  struct genl_info *info, void *arg)
{
	char buf[32];

	if (!info->attrs[TCMU_ATTR_MINOR] || !info->attrs[TCMU_ATTR_DEVICE]) {
		printf("TCMU_ATTR_MINOR or TCMU_ATTR_DEVICE not set, doing nothing\n");
		return 0;
	}

	snprintf(buf, sizeof(buf), "uio%d", nla_get_u32(info->attrs[TCMU_ATTR_MINOR]));

	switch (cmd->c_id) {
	case TCMU_CMD_ADDED_DEVICE:
		add_device(buf, nla_get_string(info->attrs[TCMU_ATTR_DEVICE]));
		break;
	case TCMU_CMD_REMOVED_DEVICE:
		remove_device(buf, nla_get_string(info->attrs[TCMU_ATTR_DEVICE]));
		break;
	default:
		printf("Unknown notification %d\n", cmd->c_id);
	}

	return 0;
}

static struct genl_cmd tcmu_cmds[] = {
	{
		.c_id		= TCMU_CMD_ADDED_DEVICE,
		.c_name		= "ADDED DEVICE",
		.c_msg_parser	= handle_netlink,
		.c_maxattr	= TCMU_ATTR_MAX,
		.c_attr_policy	= tcmu_attr_policy,
	},
	{
		.c_id		= TCMU_CMD_REMOVED_DEVICE,
		.c_name		= "REMOVED DEVICE",
		.c_msg_parser	= handle_netlink,
		.c_maxattr	= TCMU_ATTR_MAX,
		.c_attr_policy	= tcmu_attr_policy,
	},
};

static struct genl_ops tcmu_ops = {
	.o_name		= "TCM-USER",
	.o_cmds		= tcmu_cmds,
	.o_ncmds	= ARRAY_SIZE(tcmu_cmds),
};

static struct nl_sock *setup_netlink(void)
{
	struct nl_sock *sock;
	int ret;

	sock = nl_socket_alloc();
	if (!sock) {
		printf("couldn't alloc socket\n");
		exit(1);
	}

	nl_socket_disable_seq_check(sock);

	nl_socket_modify_cb(sock, NL_CB_VALID, NL_CB_CUSTOM, genl_handle_msg, NULL);

	ret = genl_connect(sock);
	if (ret < 0) {
		printf("couldn't connect\n");
		exit(1);
	}

	ret = genl_register_family(&tcmu_ops);
	if (ret < 0) {
		printf("couldn't register family\n");
		exit(1);	}

	ret = genl_ops_resolve(sock, &tcmu_ops);
	if (ret < 0) {
		printf("couldn't resolve ops, is target_core_user.ko loaded?\n");
		exit(1);
	}

	ret = genl_ctrl_resolve_grp(sock, "TCM-USER", "config");

	printf("multicast id %d\n", ret);

	ret = nl_socket_add_membership(sock, ret);
	if (ret < 0) {
		printf("couldn't add membership\n");
		exit(1);
	}

	return sock;
}

void tcmu_register_handler(struct tcmu_handler *handler)
{
	darray_append(handlers, *handler);
}

static int is_handler(const struct dirent *dirent)
{
	if (strncmp(dirent->d_name, "handler_", 8))
		return 0;

	return 1;
}

static int open_handlers(void)
{
	struct dirent **dirent_list;
	int num_handlers;
	int num_good = 0;
	int i;

	num_handlers = scandir(HANDLER_PATH, &dirent_list, is_handler, alphasort);

	if (num_handlers == -1)
		return -1;

	for (i = 0; i < num_handlers; i++) {
		char *path;
		void *handle;
		void (*handler_init)(void);
		int ret;

		ret = asprintf(&path, "%s/%s", HANDLER_PATH, dirent_list[i]->d_name);
		if (ret == -1) {
			printf("ENOMEM\n");
			continue;
		}

		handle = dlopen(path, RTLD_NOW|RTLD_LOCAL);
		if (!handle) {
			printf("Could not open handler at %s: %s\n", path, dlerror());
			free(path);
			continue;
		}

		handler_init = dlsym(handle, "handler_init");
		if (!handler_init) {
			printf("dlsym failure on %s\n", path);
			free(path);
			continue;
		}

		handler_init();

		free(path);

		num_good++;
	}

	for (i = 0; i < num_handlers; i++)
		free(dirent_list[i]);
	free(dirent_list);

	return num_good;
}

static struct tcmu_handler *find_handler(char *cfgstring)
{
	struct tcmu_handler *handler;
	size_t len;
	char *found_at;

	found_at = strchrnul(cfgstring, '/');
	len = found_at - cfgstring;

	darray_foreach(handler, handlers) {
		if (!strncmp(cfgstring, handler->subtype, len))
		    return handler;
	}

	return NULL;
}

static void handle_one_command(struct tcmu_device *dev,
		       struct tcmu_mailbox *mb,
		       struct tcmu_cmd_entry *ent)
{
	uint8_t *cdb = (void *)mb + ent->req.cdb_off;
	int i;
	bool short_cdb = cdb[0] <= 0x1f;
	int result;
	uint8_t tmp_sense_buf[TCMU_SENSE_BUFFERSIZE];

	/* Convert iovec addrs in-place to not be offsets */
	for (i = 0; i < ent->req.iov_cnt; i++)
		ent->req.iov[i].iov_base = (void *) mb +
			(size_t)ent->req.iov[i].iov_base;

	for (i = 0; i < (short_cdb ? 6 : 10); i++) {
		printf("%x ", cdb[i]);
	}

	result = dev->handler->handle_cmd(dev, cdb, ent->req.iov,
					  ent->req.iov_cnt, tmp_sense_buf);

	if (result == TCMU_NOT_HANDLED) {
		/* Tell the kernel we didn't handle it */
		char *buf = ent->rsp.sense_buffer;

		ent->rsp.scsi_status = SAM_STAT_CHECK_CONDITION;

		buf[0] = 0x70;	/* fixed, current */
		buf[2] = 0x5;	/* illegal request */
		buf[7] = 0xa;
		buf[12] = 0x20;	/* ASC: invalid command operation code */
		buf[13] = 0x0;	/* ASCQ: (none) */
	}
	else { /* handled but maybe not good */
		ent->rsp.scsi_status = result;

		if (result != SAM_STAT_GOOD) {
			printf("error! Copying sense buffer.\n");
			memcpy(ent->rsp.sense_buffer, tmp_sense_buf,
			       TCMU_SENSE_BUFFERSIZE);
		}
	}

	printf("%s\n", result != TCMU_NOT_HANDLED ? "handled" : "not handled");
}

static void poke_kernel(int fd)
{
	uint32_t buf = 0xabcdef12;

	write(fd, &buf, 4);
}

static int handle_device_events(struct tcmu_device *dev)
{
	struct tcmu_mailbox *mb = dev->map;
	struct tcmu_cmd_entry *ent = (void *) mb + mb->cmdr_off + mb->cmd_tail;
	int did_some_work = 0;

	while (ent != (void *)mb + mb->cmdr_off + mb->cmd_head) {

		if (tcmu_hdr_get_op(&ent->hdr) != TCMU_OP_CMD) {
			/* Do nothing for PAD entries */
		}
		else {
			handle_one_command(dev, mb, ent);
		}

		mb->cmd_tail = (mb->cmd_tail + tcmu_hdr_get_len(&ent->hdr)) % mb->cmdr_size;
		ent = (void *) mb + mb->cmdr_off + mb->cmd_tail;
		did_some_work = 1;
	}

	if (did_some_work)
		poke_kernel(dev->fd);

	return 0;
}

static void thread_cleanup(void *arg)
{
	struct tcmu_device *dev = arg;

	dev->handler->close(dev);
	munmap(dev->map, dev->map_len);
	close(dev->fd);
	free(dev);
}

static void *thread_start(void *arg)
{
	struct tcmu_device *dev = arg;

	pthread_cleanup_push(thread_cleanup, dev);

	handle_device_events(dev);

	while (1) {
		char buf[4];
		int ret = read(dev->fd, buf, 4);

		if (ret != 4) {
			printf("read didn't get 4! thread terminating\n");
			break;
		}

		handle_device_events(dev);
	}

	printf("thread terminating, should never happen\n");

	pthread_cleanup_pop(1);

	return NULL;
}

static int add_device(char *dev_name, char *cfgstring)
{
	struct tcmu_device *dev;
	struct tcmu_thread thread;
	char str_buf[256];
	int fd;
	int ret;
	char *ptr, *oldptr;
	int len;

	dev = calloc(1, sizeof(*dev));
	if (!dev) {
		printf("calloc failed in add_device\n");
		return -1;
	}

	snprintf(dev->dev_name, sizeof(dev->dev_name), "%s", dev_name);
	snprintf(thread.dev_name, sizeof(thread.dev_name), "%s", dev_name);

	oldptr = cfgstring;
	ptr = strchr(oldptr, '/');
	if (!ptr) {
		printf("invalid cfgstring\n");
		goto err_free;
	}

	if (strncmp(cfgstring, "tcm-user", ptr-oldptr)) {
		printf("invalid cfgstring\n");
		goto err_free;
	}

	/* Get HBA name */
	oldptr = ptr+1;
	ptr = strchr(oldptr, '/');
	if (!ptr) {
		printf("invalid cfgstring\n");
		goto err_free;
	}
	len = ptr-oldptr;
	snprintf(dev->tcm_hba_name, sizeof(dev->tcm_hba_name), "user_%.*s", len, oldptr);

	/* Get device name */
	oldptr = ptr+1;
	ptr = strchr(oldptr, '/');
	if (!ptr) {
		printf("invalid cfgstring\n");
		goto err_free;
	}
	len = ptr-oldptr;
	snprintf(dev->tcm_dev_name, sizeof(dev->tcm_dev_name), "%.*s", len, oldptr);

	/* The rest is the handler-specific cfgstring */
	oldptr = ptr+1;
	ptr = strchr(oldptr, '/');
	snprintf(dev->cfgstring, sizeof(dev->cfgstring), "%s", oldptr);

	snprintf(str_buf, sizeof(str_buf), "/dev/%s", dev_name);

	dev->fd = open(str_buf, O_RDWR);
	if (dev->fd == -1) {
		printf("could not open %s\n", str_buf);
		goto err_free;
	}

	snprintf(str_buf, sizeof(str_buf), "/sys/class/uio/%s/maps/map0/size", dev->dev_name);
	fd = open(str_buf, O_RDONLY);
	if (fd == -1) {
		printf("could not open %s\n", dev->dev_name);
		goto err_fd_close;
	}

	ret = read(fd, str_buf, sizeof(str_buf));
	close(fd);
	if (ret <= 0) {
		printf("could not read size of map0\n");
		goto err_fd_close;
	}
	str_buf[ret-1] = '\0'; /* null-terminate and chop off the \n */

	dev->map_len = strtoull(str_buf, NULL, 0);
	if (dev->map_len == ULLONG_MAX) {
		printf("could not get map length\n");
		goto err_fd_close;
	}

	dev->map = mmap(NULL, dev->map_len, PROT_READ|PROT_WRITE, MAP_SHARED, dev->fd, 0);
	if (dev->map == MAP_FAILED) {
		printf("could not mmap: %m\n");
		goto err_fd_close;
	}

	dev->handler = find_handler(dev->cfgstring);
	if (!dev->handler) {
		printf("could not find handler for %s\n", dev->dev_name);
		goto err_munmap;
	}

	ret = dev->handler->open(dev);
	if (ret < 0) {
		printf("handler open failed for %s\n", dev->dev_name);
		goto err_munmap;
	}

	/* dev will be freed by the new thread */
	ret = pthread_create(&thread.thread_id, NULL, thread_start, dev);
	if (ret) {
		printf("Could not start thread\n");
		goto err_handler_close;
	}

	darray_append(threads, thread);

	return 0;

err_handler_close:
	dev->handler->close(dev);
err_munmap:
	munmap(dev->map, dev->map_len);
err_fd_close:
	close(dev->fd);
err_free:
	free(dev);

	return -1;
}

static void cancel_thread(pthread_t thread)
{
	void *join_retval;
	int ret;

	ret = pthread_cancel(thread);
	if (ret) {
		printf("pthread_cancel failed with value %d\n", ret);
		return;
	}

	ret = pthread_join(thread, &join_retval);
	if (ret) {
		printf("pthread_join failed with value %d\n", ret);
		return;
	}

	if (join_retval != PTHREAD_CANCELED)
		printf("unexpected join retval: %p\n", join_retval);
}

static void remove_device(char *dev_name, char *cfgstring)
{
	struct tcmu_thread *thread;
	int i = 0;
	bool found = false;

	darray_foreach(thread, threads) {
		if (strncmp(thread->dev_name, dev_name, strnlen(thread->dev_name, sizeof(thread->dev_name))))
			i++;
		else {
			found = true;
			break;
		}
	}

	if (!found) {
		printf("could not remove device %s: not found\n", dev_name);
		return;
	}

	cancel_thread(thread->thread_id);

	darray_remove(threads, i);
}

static int is_uio(const struct dirent *dirent)
{
	int fd;
	char tmp_path[64];
	char buf[256];
	ssize_t ret;

	if (strncmp(dirent->d_name, "uio", 3))
		return 0;

	snprintf(tmp_path, sizeof(tmp_path), "/sys/class/uio/%s/name", dirent->d_name);

	fd = open(tmp_path, O_RDONLY);
	if (fd == -1) {
		printf("could not open %s!\n", tmp_path);
		return 0;
	}

	ret = read(fd, buf, sizeof(buf));
	if (ret <= 0 || ret >= sizeof(buf)) {
		printf("read of %s had issues\n", tmp_path);
		return 0;
	}
	buf[ret-1] = '\0'; /* null-terminate and chop off the \n */

	/* we only want uio devices whose name is a format we expect */
	if (strncmp(buf, "tcm-user", 8))
		return 0;

	return 1;
}

static int open_devices(void)
{
	struct dirent **dirent_list;
	int num_devs;
	int num_good_devs = 0;
	int i;

	num_devs = scandir("/dev", &dirent_list, is_uio, alphasort);

	if (num_devs == -1)
		return -1;

	for (i = 0; i < num_devs; i++) {
		char tmp_path[64];
		char buf[256];
		int fd;
		int ret;

		snprintf(tmp_path, sizeof(tmp_path), "/sys/class/uio/%s/name",
			 dirent_list[i]->d_name);

		fd = open(tmp_path, O_RDONLY);
		if (fd == -1) {
			printf("could not open %s!\n", tmp_path);
			continue;
		}

		ret = read(fd, buf, sizeof(buf));
		close(fd);
		if (ret <= 0 || ret >= sizeof(buf)) {
			printf("read of %s had issues\n", tmp_path);
			continue;
		}
		buf[ret-1] = '\0'; /* null-terminate and chop off the \n */

		ret = add_device(dirent_list[i]->d_name, buf);
		if (ret < 0)
			continue;

		num_good_devs++;
	}

	for (i = 0; i < num_devs; i++)
		free(dirent_list[i]);
	free(dirent_list);

	return num_good_devs;
}

static void sighandler(int signal)
{
	struct tcmu_thread *thread;

	printf("signal %d received!\n", signal);

	darray_foreach(thread, threads) {
		cancel_thread(thread->thread_id);
	}

	exit(1);
}

static struct sigaction tcmu_sigaction = {
	.sa_handler = sighandler,
};

gboolean nl_callback(GIOChannel *source,
		     GIOCondition condition,
		     gpointer data)
{
	struct nl_sock *nl_sock = data;
	int ret;

	ret = nl_recvmsgs_default(nl_sock);
	if (ret < 0) {
		printf("nl_recvmsgs_default poll returned %d", ret);
		exit(1);
	}

	return TRUE;
}

static const gchar introspection_xml[] =
	"<node>"
	" <interface name='org.kernel.TCMUService1'>"
	" <method name='SendMessage'>"
	" <arg type='s' name='message' direction='in'/>"
	" <arg type='s' name='response' direction='out'/>"
	" </method>"
	" </interface>"
	"</node>";

/*
 * Handle method calls
 */
static void handle_method_call(GDBusConnection *conn,
			       const gchar *sender,
			       const gchar *object_path,
			       const gchar *interface_name,
			       const gchar *method_name,
			       GVariant *parameters,
			       GDBusMethodInvocation *invocation,
			       gpointer user_data)
{
	if (!g_strcmp0(method_name, "SendMessage")) {
		gchar *message;
		gchar *response;
		g_variant_get(parameters, "(s)", &message);
		response = g_strdup_printf("Received message: %s", message);
		g_dbus_method_invocation_return_value(invocation, g_variant_new("(s)", response));
		g_free(message);
		g_free(response);
	}
}

/*
 * Handle property queries
 */
static GVariant *handle_get_property(GDBusConnection *conn,
				     const gchar *sender,
				     const gchar *object_path,
				     const gchar *interface_name,
				     const gchar *property_name,
				     GError **error,
				     gpointer user_data)
{
	return NULL;
}

/*
 * Handle property modifications
 */
static gboolean handle_set_property(GDBusConnection *conn,
				    const gchar *sender,
				    const gchar *object_path,
				    const gchar *interface_name,
				    const gchar *property_name,
				    GVariant *value,
				    GError **error,
				    gpointer user_data)
{
	return FALSE;
}

/*
 * Function vtable for handling methods and properties
 */
static const GDBusInterfaceVTable interface_vtable = {
	&handle_method_call,
	&handle_get_property,
	&handle_set_property
};

static void dbus_bus_acquired(GDBusConnection *connection,
			      const gchar *name,
			      gpointer user_data)
{
	GDBusNodeInfo *introspection_data = user_data;;
	guint reg_id;

	printf("bus %s acquired\n", name);

	reg_id = g_dbus_connection_register_object(connection,
						   "/org/kernel/TCMUService1",
						   introspection_data->interfaces[0],
						   &interface_vtable,
						   NULL,
						   NULL,
						   NULL);

	if (!reg_id) {
		printf("couldn't register DBus object\n");
		exit(1);
	}

}

static void dbus_name_acquired(GDBusConnection *connection,
			      const gchar *name,
			      gpointer user_data)
{
	printf("name %s acquired\n", name);
}

static void dbus_name_lost(GDBusConnection *connection,
			   const gchar *name,
			   gpointer user_data)
{
	printf("name lost\n");
}

int main()
{
	struct nl_sock *nl_sock;
	int ret;
	GMainLoop *loop;
	GIOChannel *nl_gio;
	GDBusNodeInfo *introspection_data;
	GError *error = NULL;
	guint reg_id;

	nl_sock = setup_netlink();
	if (!nl_sock) {
		printf("couldn't setup netlink\n");
		exit(1);
	}

	ret = open_handlers();
	if (ret < 0) {
		printf("couldn't open handlers\n");
		exit(1);
	}
	printf("%d handlers found\n", ret);

	ret = open_devices();
	if (ret < 0) {
		printf("couldn't open devices\n");
		exit(1);
	}
	printf("%d devices found\n", ret);

	ret = sigaction(SIGINT, &tcmu_sigaction, NULL);
	if (ret) {
		printf("couldn't set sigaction\n");
		exit(1);
	}

	/* Set up event for netlink */
	nl_gio = g_io_channel_unix_new(nl_socket_get_fd(nl_sock));
	g_io_add_watch(nl_gio, G_IO_IN, nl_callback, nl_sock);

	introspection_data = g_dbus_node_info_new_for_xml(introspection_xml, &error);
	if (!introspection_data) {
		printf("couldn't get introspection data\n");
		exit(1);
	}

	/* Set up DBus name, see callback */
	reg_id = g_bus_own_name(G_BUS_TYPE_SESSION,
				"org.kernel.TCMUService1",
				G_BUS_NAME_OWNER_FLAGS_NONE,
				dbus_bus_acquired,
				dbus_name_acquired, // name acquired
				dbus_name_lost, // name lost
				introspection_data, // user data
				NULL  // user date free func
		);

	loop = g_main_loop_new(NULL, FALSE);
	g_main_loop_run(loop);

	printf("Exiting...\n");
	g_bus_unown_name(reg_id);
	g_dbus_node_info_unref(introspection_data);
	g_main_loop_unref(loop);

	return 0;
}
