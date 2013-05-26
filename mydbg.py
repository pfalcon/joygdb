import pygtk
pygtk.require('2.0')
import gtk
import gtksourceview2
import gobject
import mimetypes
import pango
import subprocess
import fcntl
import os
import sys
import re
import ast
import optparse
import time
import errno
import source


COLOR_CUR_POS = gtk.gdk.Color(0xaaaa, 0xaaaa, 0xffff)
COLOR_BREAKPOINT = gtk.gdk.Color(0xffff, 0xaaaa, 0xaaaa)

def patch_key_event(event, keyname):
    keyval = int(gtk.gdk.keyval_from_name(keyname))
    keymap = gtk.gdk.keymap_get_default()
    keycode, group, level = keymap.get_entries_for_keyval(keyval)[0]
    event.keyval = keyval
    event.hardware_keycode = keycode
    event.group = group
    event.state = gtk.gdk.KEY_PRESS_MASK

def set_non_blocking(file):
    fd = file.fileno()
    fl = fcntl.fcntl(fd, fcntl.F_GETFL)
    fcntl.fcntl(fd, fcntl.F_SETFL, fl | os.O_NONBLOCK)

class DisasmView(gtksourceview2.View):
    __gsignals__ = {
        'key-press-event': 'override',
    }

    def __init__(self, *args, **kwargs):
        gtksourceview2.View.__init__(self, *args, **kwargs)
        self.set_wrap_mode(gtk.WRAP_WORD)
        #self.set_show_line_numbers(True)
        self.modify_font(pango.FontDescription("monospace"))
        self.set_editable(False)
        self.set_highlight_current_line(True)
        self.set_mark_category_background('position', COLOR_CUR_POS)
        self.set_mark_category_background('breakpoint', COLOR_BREAKPOINT)

        self.gdb = None
        self.pos = None
        self.func = None
        self.addr2line = {}
        # Address of first asm inst in view
        self.start_addr = None
        # Address of last asm inst in view
        self.end_addr = None

    def set_gdb(self, gdb):
        self.gdb = gdb

    def disasm_func(self, func, addr=None, cb=None, cbdata=None):
        "Need to pass in addr because gdb dumps invalid func names in disasm which itself cannot later parse"
        self.func = func
        self.load_disasm(addr or func, cb, cbdata)

    def load_disasm(self, addr, cb=None, cbdata=None):
        event, data = self.gdb.gdb.sync_cmd('-data-disassemble -s "%s" -e "%s + 0x14" -- 0' % (addr, addr))
        self.disasm_callback(event, data)

    def disasm_next(self, addr):
        def process(event, data):
            r = data['asm_insns'][1]
            self.end_addr = r['address']
            inst = r['address'][2:] + "  " + r['inst']
            it = self.buf.get_end_iter()
            self.addr2line[r['address']] = it.get_line() + 1
            self.buf.insert(it, '\n' + inst)
            self.scroll_to_mark(self.buf.get_insert(), 0)
        self.gdb.cmd('-data-disassemble -s %s -e "%s + 0x09" -- 0' % (addr, addr), ok=process)

    def disasm_callback(self, event, data):
        self.addr2line = {}
        self.start_addr = data['asm_insns'][0]['address']
        self.end_addr = data['asm_insns'][-1]['address']
        asm = []
        line = 0
        for r in data['asm_insns']:
            if r.get('offset') == '0':
                asm.append(r['func-name'] + ':')
                line += 1
            asm.append(r['address'][2:] + "  " + r['inst'])
            self.addr2line[r['address']] = line
            line += 1
        self.buf = source.Buffer()
        self.buf.set_text('\n'.join(asm))
        # TODO: Implement syntax highliting, there's no 'asm' support
        #lang = gtksourceview2.LanguageManager().get_language('asm')
        #buf.set_language(lang)
        self.buf.place_cursor(self.buf.get_start_iter())
        self.set_buffer(self.buf)

    def set_position(self, frame):
        if self.pos:
            self.buf.delete_mark(self.pos)

        addr = frame['addr']

        print frame['func'], self.func
        if frame['func'] != self.func:
            print "Loading disasm for new func:", frame['func']
            self.disasm_func(frame['func'], addr)

        if addr not in self.addr2line:
            print "Addr %s not found in Disasm view (Not Implemented)" % addr
            print self.addr2line
            return

        it = self.buf.get_iter_at_line(self.addr2line[addr])
        self.pos = self.buf.create_source_mark('pos', 'position', it)
        self.scroll_mark_onscreen(self.pos)
        self.buf.place_cursor(it)

    def do_key_press_event(self, event):
        key = gtk.gdk.keyval_name(event.keyval)
        cur_line = self.buf.get_iter_at_mark(self.buf.get_insert()).get_line()
        if key == 'Down' and cur_line == self.buf.get_line_count() - 1:
            print "Load up more asm"
            self.disasm_next(self.end_addr)
        return gtksourceview2.View.do_key_press_event(self, event)


class SourceView(gtksourceview2.View):
    __gsignals__ = {
        'key-press-event': 'override',
        'key-release-event': 'override',
        'file-changed': (gobject.SIGNAL_RUN_LAST, gobject.TYPE_NONE,
                         (gobject.TYPE_STRING,)),
    }

    def __init__(self, *args, **kwargs):
        gtksourceview2.View.__init__(self, *args, **kwargs)
        #self.set_overwrite(True)
        #self.set_show_line_marks(True)
        self.set_editable(False)
        self.set_wrap_mode(gtk.WRAP_WORD)
        self.buffers = {}
        self.breakpoints = {}
        self.pos = None
        self.set_position(None)
        self.set_mark_category_background('position', COLOR_CUR_POS)
        self.set_mark_category_background('breakpoint', COLOR_BREAKPOINT)
        self.langman = gtksourceview2.LanguageManager()

    def patch_key_event(self, event):
        key = gtk.gdk.keyval_name(event.keyval)
        #print key
        if key == 'j':
            patch_key_event(event, 'Down')
        elif key == 'k':
            patch_key_event(event, 'Up')
        elif key == 'h':
            patch_key_event(event, 'Left')
        elif key == 'l':
            patch_key_event(event, 'Right')
        elif key == 'dollar':
            patch_key_event(event, 'End')
        elif key == 'asciicircum':
            patch_key_event(event, 'Home')

    def do_key_press_event(self, event):
        key = gtk.gdk.keyval_name(event.keyval)
        if key == 'w':
            self.cursor_word_forward()
        elif key == 'b':
            self.cursor_word_backward()
        else:
            self.patch_key_event(event)
            return gtksourceview2.View.do_key_press_event(self, event)
        return True

    def do_key_release_event(self, event):
        self.patch_key_event(event)
        return gtksourceview2.View.do_key_release_event(self, event)

    def get_buffer(self, path=None):
        print "get_buffer(%s)" % path
        if path is None:
            return gtksourceview2.View.get_buffer(self)
        try:
            buf = self.buffers[path]
        except KeyError:
            buf = source.Buffer()
            lang = self.langman.guess_language(path)
            buf.set_language(lang)
            buf.set_text(open(path, 'r').read())
            self.buffers[path] = buf
            buf.filepath = path
        return buf

    def hide_position(self):
        if self.pos:
            buf = self.get_buffer()
            buf.delete_mark(self.pos)
            self.pos = None

    def set_position(self, pos):
        print "set_position(%s)" % (pos,)
        self.hide_position()
        if pos is None:
            self.set_show_line_numbers(False)
            buf = source.Buffer()
            buf.filepath = None
            self.set_buffer(buf)
            self.emit('file-changed', None)
        else:
            self.set_show_line_numbers(True)
            path, line = pos
            buf = self.get_buffer(path)
            it = buf.get_iter_at_line(line)
            self.pos = buf.create_source_mark('pos', 'position', it)
            if buf != self.get_buffer():
                buf.place_cursor(it)
                self.set_buffer(buf)
                self.emit('file-changed', path)
            self.scroll_mark_onscreen(self.pos)

    def add_breakpoint(self, id, pos):
        path, line = pos
        buf = self.get_buffer(path)
        it = buf.get_iter_at_line(line)
        mark = buf.create_source_mark(id, 'breakpoint', it)
        self.breakpoints[id] = mark

    def del_breakpoint(self, id):
        mark = self.breakpoints[id]
        buf = mark.get_buffer()
        buf.delete_mark(mark)

    def goto(self, pos):
        self.set_show_line_numbers(True)
        path, line = pos
        buf = self.get_buffer(path)
        if buf != self.get_buffer():
            self.set_buffer(buf)
            self.emit('file-changed', path)
        it = buf.get_iter_at_line(line)
        buf.place_cursor(it)
        mark = buf.get_mark('insert')
        self.scroll_mark_onscreen(mark)

def parse_value(str):
    str = re.sub(r'([\w-]+)=', r'"\1": ', str)
    return ast.literal_eval(str)

class GdbResponse:
    def __init__(self, output):
        self.event = output[0]
        if self.event == '(':
            self.data = output
        elif self.event == '~':
            self.data = parse_value(output[1:])
        elif self.event == '@':
            self.data = parse_value(output[1:])
        elif self.event == '&':
            self.data = parse_value(output[1:])
        elif self.event == '^':
            self.__parse_result(output)
        elif self.event == '*':
            self.__parse_result(output)
        elif self.event == '=':
            self.__parse_result(output)
        else:
            self.data = output[1:]

    def __parse_result(self, output):
        output = output.rstrip()
        sep = output.find(',')
        if sep != -1:
            self.event = output[:sep]
            output = output[sep+1:]
            self.data = parse_value('{' + output + '}')
        else:
            self.event = output
            self.data = None

    def __str__(self):
        return "GdbResponse(event='%s', data=%r)" % (self.event, self.data)

class GdbCommand:
    def __init__(self, *args):
        self.cmd = ' '.join(args)
        self.handle_ok = None
        self.handle_error = None
        self.returned = False
        self.result = None

class GdbDispatcher:
    def __init__(self):
        self.commands = []
        self.pending = GdbCommand('dummy')
        self.pending.prompted = False
        self.pending.returned = True
        self.handle_event = None
        self.status_changed = None
        self.gdb = subprocess.Popen(
                ['gdb', '--interpreter=mi2'],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE)
        set_non_blocking(self.gdb.stdout)
        gobject.io_add_watch(self.gdb.stdout, gobject.IO_IN, self.__read_gdb)

    def queue(self, command):
        self.commands.append(command)
        if not self.pending:
            self.__change_status(is_working=True)
            self.__exec_next()

    def is_working(self):
        return self.pending is not None

    def __change_status(self, is_working):
        if self.status_changed:
            self.status_changed(is_working)

    def __read_gdb(self, gdbout, condition):
        output = gdbout.readline()
        if output:
            print "<<< [raw] ",
            sys.stdout.write(output)
            self.__parse_response(output)
        return True

    def __parse_response(self, output):
        response = GdbResponse(output)
        print "<<< [parsed]", response
        if response.event == '(':
            if self.pending:
                self.pending.prompted = True
        elif response.event[0] == '^':
            self.pending.returned = True
            if response.event == '^error':
                if self.pending.handle_error:
                    self.pending.handle_error(response.data['msg'])
            elif self.pending.handle_ok:
                self.pending.handle_ok(response.event, response.data)
            else:
                self.pending.result = (response.event, response.data)
        elif self.handle_event:
            self.handle_event(response.event, response.data)
        if self.pending and self.pending.prompted and self.pending.returned:
            self.pending = None
            self.__exec_next()

    def __exec_next(self):
        if len(self.commands) == 0:
            self.__change_status(is_working=False)
            return
        self.pending = self.commands[0]
        self.pending.prompted = False
        self.pending.returned = False
        self.commands = self.commands[1:]
        self.gdb.stdin.write(self.pending.cmd)
        self.gdb.stdin.write('\n')
        print '>>>', self.pending.cmd

    def sync_cmd(self, command):
        "Execute command synchronously, to avoid callback spaghetti."
        while self.pending:
            try:
                self.__read_gdb(self.gdb.stdout, condition=None)
            except IOError, e:
                if e.errno != errno.EAGAIN:
                    raise
                time.sleep(0.001)
        cmd = GdbCommand(command)
        self.queue(cmd)
        while not cmd.returned:
            try:
                self.__read_gdb(self.gdb.stdout, condition=None)
            except IOError, e:
                if e.errno != errno.EAGAIN:
                    raise
                time.sleep(0.001)
        return cmd.result


def parse_breakpoints(data):
    print data
    return {}

class MyDebugger:
    NOT_LOADED = 0
    TERMINATED = 1
    STOPPED = 2
    RUNNING = 3

    STATUS_TEXT = {
        NOT_LOADED: 'not loaded',
        TERMINATED: 'not running',
        STOPPED: 'stopped',
        RUNNING: 'running',
    }

    STATUS_ICON = {
        NOT_LOADED: gtk.STOCK_INFO,
        TERMINATED: gtk.STOCK_MEDIA_STOP,
        STOPPED: gtk.STOCK_MEDIA_PAUSE,
        RUNNING: gtk.STOCK_MEDIA_PLAY,
    }

    def __init__(self):
        self.watch_for_cmd = False

        self.status = MyDebugger.NOT_LOADED
        self.gdb = GdbDispatcher()
        self.gdb.handle_event = self.__gdb_event
        self.gdb.status_changed = self.__update_gdb_status

        self.window = gtk.Window(gtk.WINDOW_TOPLEVEL)
        self.window.connect('destroy', lambda w,d=None: gtk.main_quit())
        self.window.set_default_size(640, 480)

        box = gtk.VBox(False, 0)
        splitter = gtk.VPaned()
        box.pack_start(splitter, True, True, 2)

        scroll = gtk.ScrolledWindow()
        scroll.set_policy(gtk.POLICY_AUTOMATIC, gtk.POLICY_AUTOMATIC)
        self.view = SourceView()
        self.view.modify_font(pango.FontDescription("monospace"))
        self.view.connect('file-changed', self.__file_changed)
        self.view.connect('key_press_event', self.key_pressed)
        scroll.add(self.view)
        splitter.pack1(scroll, resize=True, shrink=True)

        scroll = gtk.ScrolledWindow()
        scroll.set_policy(gtk.POLICY_AUTOMATIC, gtk.POLICY_AUTOMATIC)
        self.disasm_view = DisasmView()
        self.disasm_view.set_gdb(self)
        self.disasm_view.connect('key_press_event', self.key_pressed)
        scroll.add(self.disasm_view)
        splitter.pack2(scroll, resize=True, shrink=True)

        self.statusbar = gtk.Statusbar()
        self.statusbar.set_spacing(2)
        self.gdb_icon = gtk.Image()
        self.gdb_label = gtk.Label()
        self.gdb_label.set_width_chars(10)
        self.gdb_label.set_single_line_mode(True)
        self.gdb_label.set_alignment(0, 0.5)
        self.prog_icon = gtk.Image()
        self.prog_label = gtk.Label()
        self.prog_label.set_width_chars(20)
        self.prog_label.set_single_line_mode(True)
        self.prog_label.set_alignment(0, 0.5)
        self.statusbar.pack_start(self.gdb_icon, False, False, 0)
        self.statusbar.pack_start(self.gdb_label, False, False, 0)
        self.statusbar.pack_start(self.prog_icon, False, False, 0)
        self.statusbar.pack_start(self.prog_label, False, False, 0)
        self.__update_gdb_status(self.gdb.is_working())
        self.__update_prog_status()
        gobject.timeout_add(500, self.__timeout500)
        box.pack_start(self.statusbar, False, False, 0)

        self.cmdline = gtk.Entry()
        self.cmdline.connect('activate', self.cmd_enter)
        self.cmdline.connect('changed', self.cmd_changed)
        box.pack_start(self.cmdline, False, False, 0)

        self.window.add(box)
        self.window.show_all()
        self.cmdline.hide()
        self.view.grab_focus()

    def key_pressed(self, widget, event, data=None):
        key = gtk.gdk.keyval_name(event.keyval)
        if key == 'colon':
            self.cmdline.show()
            self.cmdline.grab_focus()
            self.cmdline.set_text(':')
            self.watch_for_cmd = True
        elif key == 'r':
            self.run()
        elif key == 'n':
            if widget is self.disasm_view:
                self.cmd('-exec-next-instruction')
            else:
                self.cmd('-exec-next')
        elif key == 's':
            if widget is self.disasm_view:
                self.cmd('-exec-step-instruction')
            else:
                self.cmd('-exec-step')
        elif key == 'f':
            self.cmd('-exec-finish')
        elif key == 'space':
            buf = self.view.get_buffer()
            path = buf.filepath
            mark = buf.get_insert()
            it = buf.get_iter_at_mark(mark)
            line = it.get_line()
            marks = buf.get_source_marks_at_line(line, 'breakpoint')
            if marks:
                for mark in marks:
                    id = mark.get_name()
                    self.delete_breakpoint(id)
            else:
                where = '%s:%d' % (path, line+1)
                self.place_breakpoint(where)
        elif key == 'c':
            self.cmd('-exec-continue')
        elif key == 'p' or key == 'P':
            if self.view.get_buffer().get_has_selection():
                b, e = self.view.get_buffer().get_selection_bounds()
                exp = b.get_slice(e)
            else:
                if key == 'p':
                    exp = self.view.get_buffer().get_symbol_under_cursor()
                else:
                    exp = self.view.get_buffer().get_call_under_cursor()
            if exp:
                self.cmd('-data-evaluate-expression', exp, ok=self.__print)
            else:
                self.__msg('no expression')
        elif key == 'P':
            pass
        else:
            return False
        return True

    def cmd_enter(self, widget, data=None):
        self.cmdline_close()

    def cmd_changed(self, widget, data=None):
        if not self.watch_for_cmd:
            return
        cmd = self.cmdline.get_text()
        print '"' + cmd + '"'
        if not cmd:
            self.cmdline_close()

    def cmdline_close(self):
        self.cmdline.hide()
        self.view.grab_focus()
        self.watch_for_cmd = False

    def main(self):
        gtk.main()

    def set_executable(self, path):
        self.cmd('-file-exec-and-symbols', path, ok=self.__loaded)

    def place_breakpoint(self, where):
        print "place_breakpoint(%s)" % where
        self.cmd('-break-insert', where, ok=self.__breakpoint_set)

    def delete_breakpoint(self, id):
        def clean_view(event, data):
            self.view.del_breakpoint(id)
        self.cmd('-break-delete', id, ok=clean_view)

    def cmd(self, *args, **kwargs):
        cmd = GdbCommand(*args)
        cmd.handle_ok = kwargs.get('ok', None)
        cmd.handle_error = self.__gdb_error
        self.gdb.queue(cmd)

    def __gdb_error(self, msg):
        dialog = gtk.MessageDialog(self.window, type=gtk.MESSAGE_ERROR,
                buttons=gtk.BUTTONS_CLOSE, message_format=msg)
        dialog.set_title('GDB error')
        dialog.run()
        dialog.destroy()

    def __loaded(self, event, data):
        self.status = MyDebugger.TERMINATED
        self.__update_prog_status()
        self.first_breakpoint = True
        self.view.set_position(None)
        self.place_breakpoint('main')
        self.disasm_view.disasm_func('main')

    def __breakpoint_set(self, event, data):
        id = data['bkpt']['number']
        try:
            path = data['bkpt']['fullname']
        except KeyError:
            msg = 'breakpoint %s set at %s'
            self.__msg(msg % (id, data['bkpt']['addr']))
        else:
            line = int(data['bkpt']['line'])-1
            self.view.add_breakpoint(id, (path, line))
            if self.first_breakpoint:
                self.view.goto((path, line))
                self.first_breakpoint = False
            msg = 'breakpoint %s set at %s:%s'
            self.__msg(msg % (id, data['bkpt']['file'], data['bkpt']['line']))


    def __gdb_event(self, event, data):
        if event == '*stopped':
            if data['reason'] == 'exited':
                self.__msg('program exited with code %s' % data['exit-code'])
                self.status = MyDebugger.TERMINATED
            elif data['reason'] == 'exited-normally':
                self.__msg('program exited normally')
                self.status = MyDebugger.TERMINATED
            elif data['reason'].startswith('exited-normally'):
                self.__msg('program exited with reason %s' % data['reason'])
                self.status = MyDebugger.TERMINATED
            else:
                self.status = MyDebugger.STOPPED
            self.__update_prog_status()
            try:
                path = data['frame']['fullname']
            except KeyError:
                self.view.set_position(None)
            else:
                line = int(data['frame']['line'])-1
                self.view.set_position((path, line))
            self.disasm_view.set_position(data['frame'])
        elif event == '*running':
            self.status = MyDebugger.RUNNING
            self.__update_prog_status()
            self.view.hide_position()

    def __file_changed(self, widget, path):
        path = 'no source' if not path else path
        title = 'mydbg: %s' % path
        self.window.set_title(title)

    def __update_gdb_status(self, is_working):
        work_icon = gtk.STOCK_MEDIA_RECORD
        gdb_status = 'working' if is_working else 'ready'
        self.gdb_label.set_text(gdb_status)
        if is_working:
            self.gdb_icon.set_from_stock(work_icon, gtk.ICON_SIZE_BUTTON)
        else:
            self.gdb_icon.clear()

    def __update_prog_status(self):
        prog_status = MyDebugger.STATUS_TEXT[self.status]
        prog_icon = MyDebugger.STATUS_ICON[self.status]
        self.prog_label.set_text('program %s' % prog_status)
        self.prog_icon.set_from_stock(prog_icon, gtk.ICON_SIZE_BUTTON)

    def __timeout500(self):
        work_icon = gtk.STOCK_MEDIA_RECORD
        if self.gdb.is_working():
            icon, size = self.gdb_icon.get_stock()
            if icon == work_icon:
                self.gdb_icon.clear()
            else:
                self.gdb_icon.set_from_stock(work_icon, gtk.ICON_SIZE_BUTTON)
        return True

    def __msg(self, msg):
        ctx = self.statusbar.get_context_id('message')
        self.statusbar.pop(ctx)
        self.statusbar.push(ctx, msg)

    def run(self):
        self.cmd('-exec-run', ok=self.__started)

    def __started(self, event, data):
        self.__msg('program started')

    def __print(self, event, data):
        self.__msg(data['value'])

if __name__ == '__main__':
    usage = 'usage: %prog [options] [executable]'
    parser = optparse.OptionParser(usage=usage)
    (options, args) = parser.parse_args()
    if len(args) > 1:
        parser.error('too many arguments')
        sys.exit(1)

    dbg = MyDebugger()
    if len(args) > 0:
        dbg.set_executable(args[0])
    dbg.main()
