/*
 *		PPP Modem handling module
 *
 *	    Written by Toshiharu OHNO (tony-o@iij.ad.jp)
 *
 *   Copyright (C) 1993, Internet Initiative Japan, Inc. All rights reserverd.
 *
 * Redistribution and use in source and binary forms are permitted
 * provided that the above copyright notice and this paragraph are
 * duplicated in all such forms and that any documentation,
 * advertising materials, and other materials related to such
 * distribution and use acknowledge that the software was developed
 * by the Internet Initiative Japan, Inc.  The name of the
 * IIJ may not be used to endorse or promote products derived
 * from this software without specific prior written permission.
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED
 * WARRANTIES OF MERCHANTIBILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 *
 * $Id: modem.c,v 1.77.2.10 1998/02/07 22:22:45 brian Exp $
 *
 *  TODO:
 */
#include <sys/param.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#include <errno.h>
#include <fcntl.h>
#include <paths.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/tty.h>
#include <unistd.h>
#include <utmp.h>
#ifdef __OpenBSD__
#include <util.h>
#else
#include <libutil.h>
#endif

#include "command.h"
#include "mbuf.h"
#include "log.h"
#include "defs.h"
#include "id.h"
#include "timer.h"
#include "fsm.h"
#include "hdlc.h"
#include "lcp.h"
#include "ip.h"
#include "modem.h"
#include "loadalias.h"
#include "vars.h"
#include "main.h"
#include "chat.h"
#include "throughput.h"
#include "async.h"
#include "bundle.h"

#undef mode

/* We're defining a physical device, and thus need the real headers. */
#include "link.h"
#include "physical.h"


#ifndef O_NONBLOCK
#ifdef O_NDELAY
#define O_NONBLOCK O_NDELAY
#endif
#endif

static void modem_StartOutput(struct link *);
static int modem_IsActive(struct link *);
static void modem_Hangup(struct link *, int);
static void modem_Destroy(struct link *);

struct physical *
modem_Create(const char *name)
{
  struct physical *p;

  p = (struct physical *)malloc(sizeof(struct physical));
  if (!p)
    return NULL;
  memset(p, '\0', sizeof *p);
  p->link.type = PHYSICAL_LINK;
  p->link.name = strdup(name);
  p->link.len = sizeof *p;
  p->link.StartOutput = modem_StartOutput;
  p->link.IsActive = modem_IsActive;
  p->link.Close = modem_Hangup;
  p->link.Destroy = modem_Destroy;
  p->fd = -1;
  p->rts_cts = 1;
  p->speed = MODEM_SPEED;
  p->parity = CS8;
  return p;
}

/* XXX-ML this should probably change when we add support for other
   types of devices */
#define	Online(modem)	((modem)->mbits & TIOCM_CD)

static void modem_LogicalClose(struct physical *);

static struct speeds {
  int nspeed;
  speed_t speed;
} speeds[] = {
#ifdef B50
  { 50, B50, },
#endif
#ifdef B75
  { 75, B75, },
#endif
#ifdef B110
  { 110, B110, },
#endif
#ifdef B134
  { 134, B134, },
#endif
#ifdef B150
  { 150, B150, },
#endif
#ifdef B200
  { 200, B200, },
#endif
#ifdef B300
  { 300, B300, },
#endif
#ifdef B600
  { 600, B600, },
#endif
#ifdef B1200
  { 1200, B1200, },
#endif
#ifdef B1800
  { 1800, B1800, },
#endif
#ifdef B2400
  { 2400, B2400, },
#endif
#ifdef B4800
  { 4800, B4800, },
#endif
#ifdef B9600
  { 9600, B9600, },
#endif
#ifdef B19200
  { 19200, B19200, },
#endif
#ifdef B38400
  { 38400, B38400, },
#endif
#ifndef _POSIX_SOURCE
#ifdef B7200
  { 7200, B7200, },
#endif
#ifdef B14400
  { 14400, B14400, },
#endif
#ifdef B28800
  { 28800, B28800, },
#endif
#ifdef B57600
  { 57600, B57600, },
#endif
#ifdef B76800
  { 76800, B76800, },
#endif
#ifdef B115200
  { 115200, B115200, },
#endif
#ifdef B230400
  { 230400, B230400, },
#endif
#ifdef EXTA
  { 19200, EXTA, },
#endif
#ifdef EXTB
  { 38400, EXTB, },
#endif
#endif				/* _POSIX_SOURCE */
  { 0, 0 }
};

static int
SpeedToInt(speed_t speed)
{
  struct speeds *sp;

  for (sp = speeds; sp->nspeed; sp++) {
    if (sp->speed == speed) {
      return (sp->nspeed);
    }
  }
  return 0;
}

speed_t
IntToSpeed(int nspeed)
{
  struct speeds *sp;

  for (sp = speeds; sp->nspeed; sp++) {
    if (sp->nspeed == nspeed) {
      return (sp->speed);
    }
  }
  return B0;
}

struct timeoutArg {
  struct bundle *bundle;
  struct physical *modem;
};

/*
 *  modem_Timeout() watches DCD signal and notifies if it's status is changed.
 *
 */
static void
modem_Timeout(void *data)
{
  struct timeoutArg *to = data;
  int ombits = to->modem->mbits;
  int change;

  StopTimer(&to->modem->link.Timer);
  StartTimer(&to->modem->link.Timer);

  if (to->modem->abort) {
    /* Something went horribly wrong */
    to->modem->abort = 0;
    link_Close(&to->modem->link, to->bundle, 0);
  } else if (to->modem->dev_is_modem) {
    if (to->modem->fd >= 0) {
      if (ioctl(to->modem->fd, TIOCMGET, &to->modem->mbits) < 0) {
	LogPrintf(LogPHASE, "ioctl error (%s)!\n", strerror(errno));
	reconnect(RECON_TRUE);
        link_Close(&to->modem->link, to->bundle, 0);
	return;
      }
    } else
      to->modem->mbits = 0;
    change = ombits ^ to->modem->mbits;
    if (change & TIOCM_CD) {
      if (to->modem->mbits & TIOCM_CD) {
        LogPrintf(LogDEBUG, "modem_Timeout: offline -> online\n");
	/*
	 * In dedicated mode, start packet mode immediate after we detected
	 * carrier.
	 */
#ifdef notyet
	if (to->modem->is_dedicated)
	  PacketMode(to->bundle, VarOpenMode);
#else
	if (mode & MODE_DEDICATED)
	  PacketMode(to->bundle, VarOpenMode);
#endif
      } else {
        LogPrintf(LogDEBUG, "modem_Timeout: online -> offline\n");
	reconnect(RECON_TRUE);
        link_Close(&to->modem->link, to->bundle, 0);
      }
    }
    else
      LogPrintf(LogDEBUG, "modem_Timeout: Still %sline\n",
                Online(to->modem) ? "on" : "off");
  } else if (!Online(to->modem)) {
    /* mbits was set to zero in modem_Open() */
    to->modem->mbits = TIOCM_CD;
  }
}

static void
modem_StartTimer(struct bundle *bundle, struct physical *modem)
{
  struct pppTimer *ModemTimer;
  static struct timeoutArg to;

  to.modem = modem;
  to.bundle = bundle;
  ModemTimer = &modem->link.Timer;

  StopTimer(ModemTimer);
  ModemTimer->state = TIMER_STOPPED;
  ModemTimer->load = SECTICKS;
  ModemTimer->func = modem_Timeout;
  ModemTimer->arg = &to;
  LogPrintf(LogDEBUG, "ModemTimer using modem_Timeout() - %p\n", modem_Timeout);
  StartTimer(ModemTimer);
}

static struct parity {
  const char *name;
  const char *name1;
  int set;
} validparity[] = {
  { "even", "P_EVEN", CS7 | PARENB },
  { "odd", "P_ODD", CS7 | PARENB | PARODD },
  { "none", "P_ZERO", CS8 },
  { NULL, 0 },
};

static int
GetParityValue(const char *str)
{
  struct parity *pp;

  for (pp = validparity; pp->name; pp++) {
    if (strcasecmp(pp->name, str) == 0 ||
	strcasecmp(pp->name1, str) == 0) {
      return pp->set;
    }
  }
  return (-1);
}

int
modem_SetParity(struct physical *modem, const char *str)
{
  struct termios rstio;
  int val;

  val = GetParityValue(str);
  if (val > 0) {
    modem->parity = val;
    tcgetattr(modem->fd, &rstio);
    rstio.c_cflag &= ~(CSIZE | PARODD | PARENB);
    rstio.c_cflag |= val;
    tcsetattr(modem->fd, TCSADRAIN, &rstio);
    return 0;
  }
  LogPrintf(LogWARN, "modem_SetParity: %s: Invalid parity\n", str);
  return -1;
}

static int
OpenConnection(char *host, char *port)
{
  struct sockaddr_in dest;
  int sock;
  struct hostent *hp;
  struct servent *sp;

  dest.sin_family = AF_INET;
  dest.sin_addr.s_addr = inet_addr(host);
  if (dest.sin_addr.s_addr == INADDR_NONE) {
    hp = gethostbyname(host);
    if (hp) {
      memcpy(&dest.sin_addr.s_addr, hp->h_addr_list[0], 4);
    } else {
      LogPrintf(LogWARN, "OpenConnection: unknown host: %s\n", host);
      return (-1);
    }
  }
  dest.sin_port = htons(atoi(port));
  if (dest.sin_port == 0) {
    sp = getservbyname(port, "tcp");
    if (sp) {
      dest.sin_port = sp->s_port;
    } else {
      LogPrintf(LogWARN, "OpenConnection: unknown service: %s\n", port);
      return (-1);
    }
  }
  LogPrintf(LogPHASE, "Connecting to %s:%s\n", host, port);

  sock = socket(PF_INET, SOCK_STREAM, 0);
  if (sock < 0) {
    return (sock);
  }
  if (connect(sock, (struct sockaddr *)&dest, sizeof dest) < 0) {
    LogPrintf(LogWARN, "OpenConnection: connection failed.\n");
    return (-1);
  }
  LogPrintf(LogDEBUG, "OpenConnection: modem fd is %d.\n", sock);
  return (sock);
}

static int
modem_lock(struct physical *modem, int tunno)
{
  int res;
  FILE *lockfile;
  char fn[MAXPATHLEN];

  if (*VarDevice != '/')
    return 0;

  if (
#ifdef notyet
      !modem->is_direct && 
#else
      !(mode & MODE_DIRECT) &&
#endif
      (res = ID0uu_lock(VarBaseDevice)) != UU_LOCK_OK) {
    if (res == UU_LOCK_INUSE)
      LogPrintf(LogPHASE, "Modem %s is in use\n", VarDevice);
    else
      LogPrintf(LogPHASE, "Modem %s is in use: uu_lock: %s\n",
                VarDevice, uu_lockerr(res));
    return (-1);
  }

  snprintf(fn, sizeof fn, "%s%s.if", _PATH_VARRUN, VarBaseDevice);
  lockfile = ID0fopen(fn, "w");
  if (lockfile != NULL) {
    fprintf(lockfile, "tun%d\n", tunno);
    fclose(lockfile);
  }
#ifndef RELEASE_CRUNCH
  else
    LogPrintf(LogALERT, "Warning: Can't create %s: %s\n", fn, strerror(errno));
#endif

  return 0;
}

static void
modem_Unlock(struct physical *modem)
{
  char fn[MAXPATHLEN];

  if (*VarDevice != '/')
    return;

  snprintf(fn, sizeof fn, "%s%s.if", _PATH_VARRUN, VarBaseDevice);
#ifndef RELEASE_CRUNCH
  if (ID0unlink(fn) == -1)
    LogPrintf(LogALERT, "Warning: Can't remove %s: %s\n", fn, strerror(errno));
#else
  ID0unlink(fn);
#endif

  if (
#ifdef notyet
      !modem->is_direct &&
#else
      !(mode & MODE_DIRECT) &&
#endif
      ID0uu_unlock(VarBaseDevice) == -1)
    LogPrintf(LogALERT, "Warning: Can't uu_unlock %s\n", fn);
}

static void
modem_Found(struct physical *modem)
{
  throughput_start(&modem->link.throughput);
  modem->connect_count++;
  LogPrintf(LogPHASE, "Connected!\n");
}

int
modem_Open(struct physical *modem, struct bundle *bundle)
{
  struct termios rstio;
  int oldflag;
  char *host, *port;
  char *cp;
  char tmpDeviceList[sizeof VarDeviceList];
  char *tmpDevice;

  if (modem->fd >= 0)
    LogPrintf(LogDEBUG, "modem_Open: Modem is already open!\n");
    /* We're going back into "term" mode */
  else if (
#ifdef notyet
	   modem->is_direct
#else
	   mode & MODE_DIRECT
#endif
	   ) {
    struct cmdargs arg;
    arg.cmd = NULL;
    arg.data = (const void *)VAR_DEVICE;
    arg.bundle = bundle;
    if (isatty(STDIN_FILENO)) {
      LogPrintf(LogDEBUG, "modem_Open(direct): Modem is a tty\n");
      cp = ttyname(STDIN_FILENO);
      arg.argc = 1;
      arg.argv = (char const *const *)&cp;
      SetVariable(&arg);
      if (modem_lock(modem, bundle->unit) == -1) {
        close(STDIN_FILENO);
        return -1;
      }
      modem->fd = STDIN_FILENO;
      modem_Found(modem);
    } else {
      LogPrintf(LogDEBUG, "modem_Open(direct): Modem is not a tty\n");
      arg.argc = 0;
      arg.argv = NULL;
      SetVariable(&arg);
      /* We don't call modem_Timeout() with this type of connection */
      modem_Found(modem);
      return modem->fd = STDIN_FILENO;
    }
  } else {
    strncpy(tmpDeviceList, VarDeviceList, sizeof tmpDeviceList - 1);
    tmpDeviceList[sizeof tmpDeviceList - 1] = '\0';

    for(tmpDevice=strtok(tmpDeviceList, ","); tmpDevice && (modem->fd < 0);
	tmpDevice=strtok(NULL,",")) {
      strncpy(VarDevice, tmpDevice, sizeof VarDevice - 1);
      VarDevice[sizeof VarDevice - 1]= '\0';
      VarBaseDevice = strrchr(VarDevice, '/');
      VarBaseDevice = VarBaseDevice ? VarBaseDevice + 1 : "";

      if (strncmp(VarDevice, "/dev/", 5) == 0) {
	if (modem_lock(modem, bundle->unit) == -1) {
	  modem->fd = -1;
	}
	else {
	  modem->fd = ID0open(VarDevice, O_RDWR | O_NONBLOCK);
	  if (modem->fd < 0) {
	    LogPrintf(LogERROR, "modem_Open failed: %s: %s\n", VarDevice,
		      strerror(errno));
	    modem_Unlock(modem);
	    modem->fd = -1;
	  }
	  else {
	    modem_Found(modem);
	    LogPrintf(LogDEBUG, "modem_Open: Modem is %s\n", VarDevice);
	  }
	}
      } else {
	/* PPP over TCP */
	cp = strchr(VarDevice, ':');
	if (cp) {
	  *cp = '\0';
	  host = VarDevice;
	  port = cp + 1;
	  if (*host && *port) {
	    modem->fd = OpenConnection(host, port);
	    *cp = ':';		/* Don't destroy VarDevice */
	    if (modem->fd < 0)
	      return (-1);
	    modem_Found(modem);
	    LogPrintf(LogDEBUG, "modem_Open: Modem is socket %s\n", VarDevice);
	  } else {
	    *cp = ':';		/* Don't destroy VarDevice */
	    LogPrintf(LogERROR, "Invalid host:port: \"%s\"\n", VarDevice);
	    return (-1);
	  }
	} else {
	  LogPrintf(LogERROR,
		    "Device (%s) must be in /dev or be a host:port pair\n",
		    VarDevice);
	  return (-1);
	}
      }
    }

    if (modem->fd < 0)
       return modem->fd;
  }

  /*
   * If we are working on tty device, change it's mode into the one desired
   * for further operation. In this implementation, we assume that modem is
   * configuted to use CTS/RTS flow control.
   */
  modem->mbits = 0;
  modem->dev_is_modem = isatty(modem->fd) || Physical_IsSync(modem);
  if (Physical_IsSync(modem))
    nointr_sleep(1);
  if (modem->dev_is_modem && !Physical_IsSync(modem)) {
    tcgetattr(modem->fd, &rstio);
    modem->ios = rstio;
    LogPrintf(LogDEBUG, "modem_Open: modem = %d\n", modem->fd);
    LogPrintf(LogDEBUG, "modem_Open: modem (get): iflag = %x, oflag = %x,"
	      " cflag = %x\n", rstio.c_iflag, rstio.c_oflag, rstio.c_cflag);
    cfmakeraw(&rstio);
    if (modem->rts_cts)
      rstio.c_cflag |= CLOCAL | CCTS_OFLOW | CRTS_IFLOW;
    else {
      rstio.c_cflag |= CLOCAL;
      rstio.c_iflag |= IXOFF;
    }
    rstio.c_iflag |= IXON;
    if (
#ifdef notyet
	!modem->is_dedicated
#else
	!(mode & MODE_DEDICATED)
#endif
	)
      rstio.c_cflag |= HUPCL;
    if (
#ifdef notyet
	!modem->is_direct
#else
	!(mode & MODE_DIRECT)
#endif
	) {

      /*
       * If we are working as direct mode, don't change tty speed.
       */
      rstio.c_cflag &= ~(CSIZE | PARODD | PARENB);
      rstio.c_cflag |= modem->parity;
      if (cfsetspeed(&rstio, IntToSpeed(modem->speed)) == -1) {
	LogPrintf(LogWARN, "Unable to set modem speed (modem %d to %d)\n",
		  modem->fd, modem->speed);
      }
    }
    tcsetattr(modem->fd, TCSADRAIN, &rstio);
    LogPrintf(LogDEBUG, "modem (put): iflag = %x, oflag = %x, cflag = %x\n",
	      rstio.c_iflag, rstio.c_oflag, rstio.c_cflag);

    if (
#ifdef notyet
	!modem->is_direct
#else
	!(mode & MODE_DIRECT)
#endif
	)
      if (ioctl(modem->fd, TIOCMGET, &modem->mbits)) {
        LogPrintf(LogERROR, "modem_Open: Cannot get modem status: %s\n",
		  strerror(errno));
        modem_LogicalClose(modem);
	return (-1);
      }
    LogPrintf(LogDEBUG, "modem_Open: modem control = %o\n", modem->mbits);

    oldflag = fcntl(modem->fd, F_GETFL, 0);
    if (oldflag < 0) {
      LogPrintf(LogERROR, "modem_Open: Cannot get modem flags: %s\n",
		strerror(errno));
      modem_LogicalClose(modem);
      return (-1);
    }
    (void) fcntl(modem->fd, F_SETFL, oldflag & ~O_NONBLOCK);
  }
  modem_StartTimer(bundle, modem);

  return (modem->fd);
}

int
modem_Speed(struct physical *modem)
{
  struct termios rstio;

  tcgetattr(modem->fd, &rstio);
  return (SpeedToInt(cfgetispeed(&rstio)));
}

/*
 * Put modem tty line into raw mode which is necessary in packet mode operation
 */
int
modem_Raw(struct physical *modem)
{
  struct termios rstio;
  int oldflag;

  if (!isatty(modem->fd) || Physical_IsSync(modem))
    return (0);
  if (
#ifdef notyet
      !modem->is_direct &&
#else
      !(mode & MODE_DIRECT) &&
#endif
      modem->fd >= 0 && !Online(modem)) {
    LogPrintf(LogDEBUG, "modem_Raw: modem = %d, mbits = %x\n",
			  modem->fd, modem->mbits);
  }
  tcgetattr(modem->fd, &rstio);
  cfmakeraw(&rstio);
  if (modem->rts_cts)
    rstio.c_cflag |= CLOCAL | CCTS_OFLOW | CRTS_IFLOW;
  else
    rstio.c_cflag |= CLOCAL;

  if (
#ifdef notyet
      !modem->is_dedicated
#else
      !(mode & MODE_DEDICATED)
#endif
      )
    rstio.c_cflag |= HUPCL;
  tcsetattr(modem->fd, TCSADRAIN, &rstio);
  oldflag = fcntl(modem->fd, F_GETFL, 0);
  if (oldflag < 0)
    return (-1);
  (void) fcntl(modem->fd, F_SETFL, oldflag | O_NONBLOCK);
  return (0);
}

static void
modem_Unraw(struct physical *modem)
{
  int oldflag;

  if (isatty(modem->fd) && !Physical_IsSync(modem)) {
    tcsetattr(modem->fd, TCSAFLUSH, &modem->ios);
    oldflag = fcntl(modem->fd, F_GETFL, 0);
    if (oldflag < 0)
      return;
    (void) fcntl(modem->fd, F_SETFL, oldflag & ~O_NONBLOCK);
  }
}

static void
modem_PhysicalClose(struct physical *modem)
{
  LogPrintf(LogDEBUG, "modem_PhysicalClose\n");
  close(modem->fd);
  modem->fd = -1;
  throughput_log(&modem->link.throughput, LogPHASE, "Modem");
}

static void
modem_Hangup(struct link *l, int dedicated_force)
{
  struct termios tio;
  struct physical *modem = (struct physical *)l;

  LogPrintf(LogDEBUG, "Hangup modem (%s)\n",
            modem->fd >= 0 ? "open" : "closed");

  if (modem->fd < 0)
    return;

  StopTimer(&modem->link.Timer);
  throughput_stop(&modem->link.throughput);

  if (TermMode) {
    LogPrintf(LogDEBUG, "modem_Hangup: Not in 'term' mode\n");
    return;
  }

  if (!isatty(modem->fd)) {
    modem->mbits &= ~TIOCM_DTR;
    modem_PhysicalClose(modem);
    return;
  }

  if (modem->fd >= 0 && Online(modem)) {
    modem->mbits &= ~TIOCM_DTR;
    tcgetattr(modem->fd, &tio);
    if (cfsetspeed(&tio, B0) == -1) {
      LogPrintf(LogWARN, "Unable to set modem to speed 0\n");
    }
    tcsetattr(modem->fd, TCSANOW, &tio);
    nointr_sleep(1);
  }

  if (modem->fd >= 0) {
    char ScriptBuffer[SCRIPT_LEN];

    strncpy(ScriptBuffer, VarHangupScript, sizeof ScriptBuffer - 1);
    ScriptBuffer[sizeof ScriptBuffer - 1] = '\0';
    LogPrintf(LogDEBUG, "modem_Hangup: Script: %s\n", ScriptBuffer);
    if (dedicated_force ||
#ifdef notyet
	!modem->is_dedicated
#else
	!(mode & MODE_DEDICATED)
#endif
	) {
      DoChat(modem, ScriptBuffer);
      tcflush(modem->fd, TCIOFLUSH);
      modem_Unraw(modem);
      modem_LogicalClose(modem);
    } else {
      /*
       * If we are working as dedicated mode, never close it until we are
       * directed to quit program.
       */
      modem->mbits |= TIOCM_DTR;
      ioctl(modem->fd, TIOCMSET, &modem->mbits);
      DoChat(modem, ScriptBuffer);
    }
  }
}

static void
modem_Destroy(struct link *l)
{
  struct physical *p;

  p = link2physical(l);
  if (p->fd != -1)
    modem_Hangup(l, 1);
  free(l->name);
  free(p);
}

static void
modem_LogicalClose(struct physical *modem)
{
  LogPrintf(LogDEBUG, "modem_LogicalClose\n");
  if (modem->fd >= 0) {
    modem_PhysicalClose(modem);
    if (Utmp) {
      struct utmp ut;
      strncpy(ut.ut_line, VarBaseDevice, sizeof ut.ut_line - 1);
      ut.ut_line[sizeof ut.ut_line - 1] = '\0';
      if (logout(ut.ut_line))
        logwtmp(ut.ut_line, "", ""); 
      else
        LogPrintf(LogERROR, "modem_LogicalClose: No longer logged in on %s\n",
		  ut.ut_line);
      Utmp = 0;
    }
    modem_Unlock(modem);
  }
}

static void
modem_StartOutput(struct link *l)
{
  struct physical *modem = (struct physical *)l;
  int nb, nw;

  if (modem->out == NULL) {
    if (link_QueueLen(l) == 0)
      IpStartOutput(l);

    modem->out = link_Dequeue(l);
  }

  if (modem->out) {
    nb = modem->out->cnt;
    nw = write(modem->fd, MBUF_CTOP(modem->out), nb);
    LogPrintf(LogDEBUG, "modem_StartOutput: wrote: %d(%d) to %d\n",
              nw, nb, modem->fd);
    if (nw > 0) {
      LogDumpBuff(LogDEBUG, "modem_StartOutput: modem write",
		  MBUF_CTOP(modem->out), nw);
      modem->out->cnt -= nw;
      modem->out->offset += nw;
      if (modem->out->cnt == 0) {
	modem->out = mbfree(modem->out);
	LogPrintf(LogDEBUG, "modem_StartOutput: mbfree\n");
      }
    } else if (nw < 0) {
      if (errno != EAGAIN) {
	LogPrintf(LogERROR, "modem write (%d): %s\n", modem->fd,
		  strerror(errno));
        reconnect(RECON_TRUE);
        modem->abort = 1;
      }
    }
  }
}

static int
modem_IsActive(struct link *l)
{
  return ((struct physical *)l)->fd >= 0;
}

int
modem_Dial(struct physical *modem, struct bundle *bundle)
{
  char ScriptBuffer[SCRIPT_LEN];
  int excode;

  strncpy(ScriptBuffer, VarDialScript, sizeof ScriptBuffer - 1);
  ScriptBuffer[sizeof ScriptBuffer - 1] = '\0';
  if ((excode = DoChat(modem, ScriptBuffer)) > 0) {
    if (VarTerm)
      fprintf(VarTerm, "dial OK!\n");
    strncpy(ScriptBuffer, VarLoginScript, sizeof ScriptBuffer - 1);
    if ((excode = DoChat(modem, ScriptBuffer)) > 0) {
      struct timeoutArg to;

      VarAltPhone = NULL;
      if (VarTerm)
	fprintf(VarTerm, "login OK!\n");
      to.modem = modem;
      to.bundle = bundle;
      modem_Timeout(&to);
      return EX_DONE;
    } else if (excode == -1)
      excode = EX_SIG;
    else {
      LogPrintf(LogWARN, "modem_Dial: login failed.\n");
      excode = EX_NOLOGIN;
    }
    modem_Timeout(modem);		/* Dummy call to check modem status */
  } else if (excode == -1)
    excode = EX_SIG;
  else {
    LogPrintf(LogWARN, "modem_Dial: dial failed.\n");
    excode = EX_NODIAL;
  }
  modem_Hangup(&modem->link, 0);
  return (excode);
}

int
modem_ShowStatus(struct cmdargs const *arg)
{
  const char *dev;
  struct physical *modem = arg->bundle->physical;
#ifdef TIOCOUTQ
  int nb;
#endif

  if (!VarTerm)
    return 1;

  dev = *VarDevice ? VarDevice : "network";

  fprintf(VarTerm, "device: %s  speed: ", dev);
  if (Physical_IsSync(modem))
    fprintf(VarTerm, "sync\n");
  else
    fprintf(VarTerm, "%d\n", modem->speed);

  switch (modem->parity & CSIZE) {
  case CS7:
    fprintf(VarTerm, "cs7, ");
    break;
  case CS8:
    fprintf(VarTerm, "cs8, ");
    break;
  }
  if (modem->parity & PARENB) {
    if (modem->parity & PARODD)
      fprintf(VarTerm, "odd parity, ");
    else
      fprintf(VarTerm, "even parity, ");
  } else
    fprintf(VarTerm, "no parity, ");

  fprintf(VarTerm, "CTS/RTS %s.\n", (modem->rts_cts ? "on" : "off"));

  if (LogIsKept(LogDEBUG))
    fprintf(VarTerm, "fd = %d, modem control = %o\n", modem->fd, modem->mbits);
  fprintf(VarTerm, "connect count: %d\n", modem->connect_count);
#ifdef TIOCOUTQ
  if (modem->fd >= 0)
    if (ioctl(modem->fd, TIOCOUTQ, &nb) >= 0)
      fprintf(VarTerm, "outq: %d\n", nb);
    else
      fprintf(VarTerm, "outq: ioctl probe failed: %s\n", strerror(errno));
#endif
  fprintf(VarTerm, "outqlen: %d\n", link_QueueLen(&modem->link));
  fprintf(VarTerm, "DialScript  = %s\n", VarDialScript);
  fprintf(VarTerm, "LoginScript = %s\n", VarLoginScript);
  fprintf(VarTerm, "PhoneNumber(s) = %s\n", VarPhoneList);

  fprintf(VarTerm, "\n");
  throughput_disp(&modem->link.throughput, VarTerm);

  return 0;
}


/* Dummy linker functions, to keep this quiet.  Might end up a full
   regression test later, right now it is just to be able to track
   external symbols. */
#ifdef TESTMAIN
int main(void) {}

void LogPrintf(int i, const char *a, ...) {}
int  LogIsKept(int garble) {  return 0; }
int  Physical_IsSync(struct physical *phys) {return 0;}
int  DoChat(struct physical *a, char *b) {return 0;}

int mode;

#endif

