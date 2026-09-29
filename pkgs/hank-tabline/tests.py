"""UI regression checks; requires Python's pynvim package and Neovim 0.12+."""
import argparse
import json
from pathlib import Path
import tempfile

import pynvim

parser = argparse.ArgumentParser()
parser.add_argument('--nvim', default='nvim')
parser.add_argument('--init', default='NONE')
parser.add_argument('--underline', action='store_true')
parser.add_argument('--project', action='store_true')
parser.add_argument('--no-animate', action='store_true')
parser.add_argument('--capture-json')
parser.add_argument('--capture-explorer-json')
args = parser.parse_args()
header_rows = 2 if args.underline else 1
bare = args.init == 'NONE'
here = Path(__file__).parent
# Both the bare setup below and Hank's config use a 30-column left sidebar block.
block_width = 30
n = pynvim.attach('child', argv=[args.nvim, '--embed', '--headless', '-u', args.init, '-i', 'NONE'])
n.ui_attach(120,32, rgb=True, ext_linegrid=True)

def lua(code, *values):
    return n.exec_lua(code, *values)

def settle():
    lua('vim.wait(360)')
    n.command('redraw!')

def row(number):
    # The right half of a wide character reads as '', so pad it to keep index == column.
    return lua('local t={} for c=1,vim.o.columns do local s=vim.fn.screenstring(...,c) t[c]=s=="" and "\\0" or s end return table.concat(t)', number)

def attr(screenrow, col):
    return lua('return vim.fn.screenattr(...)', screenrow, col)

def click(screenrow, col):
    n.api.input_mouse('left','press','',0,screenrow,col)
    n.api.input_mouse('left','release','',0,screenrow,col)
    settle()

def ordinary_windows():
    return lua('local t={} for _,w in ipairs(vim.api.nvim_tabpage_list_wins(0)) do if vim.api.nvim_win_get_config(w).relative=="" then t[#t+1]=w end end return t')

def filetypes():
    return lua('local t={} for _,w in ipairs(vim.api.nvim_tabpage_list_wins(0)) do if vim.api.nvim_win_get_config(w).relative=="" then t[#t+1]=vim.bo[vim.api.nvim_win_get_buf(w)].filetype end end return t')

def layout():
    return lua("return require('hank-tabline').layout()")

def panel_col(id):
    # Screen column (0-based) of a panel's glyph; its item is ' <glyph> '.
    return next(item['col'] for item in layout() if item['id']==id)+1

def tabs_col():
    return min(item['col'] for item in layout() if item['section']=='buffers')

def panel_icons(side='left'):
    return ''.join(item['text'] for item in lua("return require('hank-panels').section(...).items()",side))

def lit(accent):
    return lua('local t={} for c=1,vim.o.columns do if vim.fn.screenattr(2,c)==... then t[#t+1]=c end end return t',accent)

def block_open():
    return any(str(item['section']).startswith('left-block') for item in layout())

def strips():
    return lua('local t={} for _,w in ipairs(vim.api.nvim_tabpage_list_wins(0)) do if vim.bo[vim.api.nvim_win_get_buf(w)].filetype=="hank_tabline_strip" then t[#t+1]=w end end return t')

def bottom_layout():
    return lua("return require('hank-tabline').layout('bottom')")

def check_bottom():
    # The tabs cover the separator row above the bottom panel; with the rail, its winbar too.
    win=lua("return require('hank-panels').window('bottom')")
    top,left=n.api.win_get_position(win)
    width=n.api.win_get_width(win)
    strip=strips()
    assert len(strip)==1,strip
    assert n.api.win_get_position(strip[0])==[top-1,left] and n.api.win_get_width(strip[0])==width,(top,left,width)
    assert n.api.win_get_height(strip[0])==header_rows
    assert n.api.get_option_value('winbar',{'win':win})==(' ' if args.underline else '')
    if args.underline:
        assert set(row(top+1)[left:left+width]) <= set('━╸╺'),row(top+1)
    return win,top,left,width

def check_track():
    bars=lua('local t={} for _,w in ipairs(vim.api.nvim_tabpage_list_wins(0)) do if vim.bo[vim.api.nvim_win_get_buf(w)].filetype=="hank_tabline" then t[#t+1]=w end end return t')
    if args.underline:
        assert len(bars)==1 and set(row(2)) <= set('━╸╺ '),row(2)
        if block_open():
            # The rail breaks in the gap between the sidebar block and the buffer tabs.
            assert row(2)[block_width]==' ' and ' ' not in row(2)[:block_width],row(2)
        else:
            assert ' ' not in row(2),row(2)
    else:
        assert not bars,bars

def capture(path):
    cells=lua('local rows={} for r=1,12 do rows[r]={} for c=1,vim.o.columns do rows[r][c]={vim.fn.screenstring(r,c),vim.fn.screenattr(r,c)} end end return rows')
    attrs={0:{}}
    for msg in n._session._pending_messages:
        if msg.type=='notification' and msg.name=='redraw':
            for event in msg.args:
                if event[0]=='hl_attr_define':
                    for entry in event[1:]:attrs[entry[0]]=entry[1]
    Path(path).write_text(json.dumps({'cells':cells,'attrs':attrs}))

try:
    if not bare:
        assert lua("return package.loaded['hank-tabline'] ~= nil and _G.MiniTabline == nil"), n.command_output('messages')
    lua('vim.opt.rtp:prepend(...)', str(here))
    lua('vim.opt.rtp:prepend(...)', str(here.parent/'hank-panels'))
    lua('''
      local underline, project, animate, width = ...
      vim.o.laststatus=3; vim.o.hidden=true; vim.o.mouse='a'; vim.o.cmdheight=1
      if not package.loaded['hank-tabline'] then
        local panels, a = require('hank-panels'), require('hank-panels.adapters')
        local function fake(ft, command)
          return function()
            vim.cmd(command); vim.bo.buftype='nofile'; vim.bo.bufhidden='wipe'; vim.bo.filetype=ft
          end
        end
        panels.setup({panels={
          a.window({id='tree',icon=0xf024b,icon_inactive=0xf0256,ft='faketree',open=fake('faketree','topleft '..width..'vnew')}),
          a.window({id='outline',icon=0xf0645,icon_inactive=0xf13d2,ft='fakeoutline',open=fake('fakeoutline','topleft '..width..'vnew')}),
          a.window({id='info',side='right',icon=0xf02fc,icon_inactive=0xf02fd,ft='fakeinfo',open=fake('fakeinfo','botright 12vnew')}),
          a.window({id='logs',side='bottom',icon=0xf018d,label='Logs',ft='fakelogs',open=fake('fakelogs','botright 8new')}),
          a.window({id='errors',side='bottom',icon=0xf0028,icon_inactive=0xf05d6,label=function() return 'Errors 3' end,
            ft='fakeerrors',open=fake('fakeerrors','botright 8new')}),
        }})
        require('hank-tabline').setup({underline=underline,project=project,animate=animate,
          sidebars={left={width=width,sections={panels.section('left')}},right={width=12,sections={panels.section('right')}}},
          bottom={sections={panels.section('bottom')},anchor=function() return panels.window('bottom') end},
          palette=function() return {
            crust='#171c1f',mantle='#191e21',base='#1e2528',green='#cbe3b3',overlay2='#839e9a',overlay0='#58686d'
          } end})
      end
    ''',args.underline,args.project,not args.no_animate,block_width)
    buffers=[]
    with tempfile.TemporaryDirectory(prefix='hank-tabline-') as directory:
        for name in ('flake.nix','Justfile','home-utils.nix'):
            b=n.api.create_buf(True,False)
            n.api.buf_set_name(b,str(Path(directory)/name))
            n.api.buf_set_lines(b,0,-1,False,['first line is visible','','last line'])
            n.api.set_option_value('modified',False,{'buf':b})
            n.api.set_current_buf(b)
            buffers.append(b.number)
        # Drop the original unnamed buffer from the list, as :edit normally does.
        lua('if vim.api.nvim_buf_is_valid(1) and vim.api.nvim_buf_get_name(1)=="" then vim.bo[1].buflisted=false end')
        settle()
        assert len(ordinary_windows())==1
        prefix_width=tabs_col()
        title=' \uf07b nix-config ' if args.project else ''
        # With every sidebar closed there is no block: the title leads the row.
        assert prefix_width==len(title) and row(1).startswith(title+' flake.nix  Justfile  home-utils.nix '),row(1)
        assert args.project or '\uf07b' not in row(1),row(1)
        icons=panel_icons()
        assert not block_open() and not any(glyph in row(1) for glyph in icons.split()),row(1)
        check_track()
        track_attr=attr(2,1)
        assert 'first line is visible' in row(header_rows+1),row(header_rows+1)
        selected=n.api.get_hl(0,{'name':'HankTablineSelected','link':False})
        assert selected['bg']==int('cbe3b3',16) and selected['bold']
        print('PASS: no sidebar block while sidebars are closed, title leads the row, Evergarden palette, unobstructed first file line')
        original=n.api.get_current_win()
        n.command('wincmd k');settle()
        assert n.api.get_current_win()==original
        for command in ('vsplit','split'):
            n.command(command);settle()
        assert len(ordinary_windows())==3
        for w in ordinary_windows():
            pos=n.api.win_get_position(w)
            assert n.api.get_option_value('winbar',{'win':w})==(' ' if args.underline and pos[0]==1 else '')
        n.command('only');settle();assert len(ordinary_windows())==1
        n.command('tabnew');settle();assert len(ordinary_windows())==1
        n.command('tabclose');settle();assert len(ordinary_windows())==1
        print('PASS: split navigation, :only, and tabpage lifecycle add no ordinary windows')
        # Actual mouse input exercises the native tab callback and the second-row map.
        for screenrow, col, expected in ((0,3,buffers[0]),(header_rows-1,14,buffers[1])):
            click(screenrow,prefix_width+col)
            assert n.api.get_current_buf().number==expected,(screenrow,n.api.get_current_buf().number)
        lua('vim.api.nvim_buf_set_lines(0,-1,-1,false,{"modified"})');settle()
        assert 'Justfile ●' in row(1)
        lua('vim.bo.modified=false');settle()
        assert '●' not in row(1)
        assert row(1)[:prefix_width]==title,row(1)
        # The project title and the empty stretch are inert.
        inert=[100]+([2] if args.project else [])
        for screenrow in range(header_rows):
            for col in inert:
                before=n.api.get_current_buf().number
                click(screenrow,col)
                assert n.api.get_current_buf().number==before and len(ordinary_windows())==1,(screenrow,col)
        original_cwd=lua('return vim.fn.getcwd(-1,0)')
        project=Path(directory)/'项目%name'
        project.mkdir()
        if args.project:
            lua('vim.cmd.tcd({args={vim.fn.fnameescape(...)},mods={silent=true}})',str(project));settle()
            assert row(1).replace('\0','').startswith(' \uf07b 项目%name  flake.nix'),row(1)
            lua('vim.cmd.tcd({args={vim.fn.fnameescape(...)},mods={silent=true}})',original_cwd);settle()
            assert row(1)[:prefix_width]==title
        print('PASS: title placement, directory changes, inert gaps, offset clicks and modified indicators')
        if args.underline:
            n.command(f'buffer {buffers[0]}');settle()
            accent=attr(2,prefix_width+4)
            first=lit(accent)
            n.command(f'buffer {buffers[2]}');settle();last=lit(accent)
            assert first and last and first!=last and all(c>prefix_width for c in first+last),(first,last)
            n.command(f'buffer {buffers[0]}');settle()
            n.command(f'buffer {buffers[2]}');lua('vim.wait(150)');n.command('redraw!')
            midway=lit(accent)
            assert midway==last if args.no_animate else midway not in (first,last),(first,midway,last)
            settle();assert lit(accent)==last
            print('PASS: rail', 'jumps without animation' if args.no_animate else 'glides between tabs')
        if bare:
            tabs=row(1)[prefix_width:prefix_width+30]
            lua("require('hank-panels').open('tree')");settle()
            assert block_open() and tabs_col()==block_width+1,(layout(),row(1))
            block=row(1)[:block_width]
            # Icons keep a fixed spot one cell off the gap, whatever the title's length.
            start=block_width-len(icons)-1
            tree,outline=panel_col('tree'),panel_col('outline')
            assert block.startswith(title) and row(1)[start:start+len(icons)]!='' and row(1)[tree]=='\U000f024b',(block,icons)
            assert block[start:start+len(icons)].replace('\U000f024b','\U000f0256')==icons,(block,icons)
            assert row(1)[block_width]==' ' and row(1)[block_width+1:].startswith(tabs[:20]),row(1)
            assert attr(1,start)!=attr(1,100),'sidebar block shares the tab row background'
            # The sidebar's own column starts right under the gap.
            assert n.api.win_get_width(ordinary_windows()[0])==block_width
            check_track()
            if args.underline:
                assert attr(2,start)!=attr(2,100),'sidebar block shares the rail background'
                assert attr(2,tree+1)!=attr(2,start),'panel segment not lit'
            for col in (start-1,block_width):
                click(0,col)
                assert 'faketree' in filetypes() and len(ordinary_windows())==2,col
            if args.project:
                lua('vim.cmd.tcd({args={vim.fn.fnameescape(...)},mods={silent=true}})',str(project));settle()
                assert '项目%name' in row(1)[:block_width].replace('\0','') and panel_col('tree')==tree,row(1)
                lua('vim.cmd.tcd({args={vim.fn.fnameescape(...)},mods={silent=true}})',original_cwd);settle()
            click(0,outline)
            assert 'fakeoutline' in filetypes() and 'faketree' not in filetypes(),filetypes()
            assert row(1)[tree]=='\U000f0256' and row(1)[outline]=='\U000f0645' and panel_col('outline')==outline,row(1)
            lua("require('hank-panels').open('info')");settle()
            info=next(item for item in layout() if item['id']=='info')
            assert info['col']==120-12+1 and row(1)[info['col']-1]==' ',(info,row(1))
            assert {'fakeoutline','fakeinfo'} <= set(filetypes()),filetypes()
            click(0,info['col']+1)
            assert 'fakeinfo' not in filetypes() and not any(item['id']=='info' for item in layout()),filetypes()
            click(header_rows-1,outline)
            assert 'fakeoutline' not in filetypes() and not block_open(),filetypes()
            assert len(ordinary_windows())==1 and tabs_col()==prefix_width and row(1)[prefix_width:prefix_width+30]==tabs,row(1)
            check_track()
            print('PASS: sidebar block only with a panel open: width, surface, gap, fixed icons, one panel per side, both sides, header and rail clicks')
            owner="local p=require('hank-panels').at() return p and p.id"
            assert not lua("return require('hank-panels').cycle(1)")
            lua("require('hank-panels').open('tree')");settle()
            assert lua(owner)=='tree'
            for step,expected in ((1,'outline'),(1,'tree'),(-1,'outline'),(3,'tree')):
                assert lua("return require('hank-panels').cycle(...)",step);settle()
                assert lua(owner)==expected and len(ordinary_windows())==2,(step,lua(owner),filetypes())
            lua("require('hank-panels').close('tree')");settle()
            assert len(ordinary_windows())==1
            print('PASS: cycling inside a sidebar walks its side and wraps; outside it reports false')
            assert not strips() and not bottom_layout()
            lua("require('hank-panels').open('logs')");settle()
            win,top,left,width=check_bottom()
            lua("vim.api.nvim_buf_set_lines(vim.api.nvim_win_get_buf(...),0,-1,false,{'bottom first line'})",win);settle()
            labels=row(top)
            logs,errors=(next(item for item in bottom_layout() if item['id']==id) for id in ('logs','errors'))
            assert labels[logs['col']:logs['col']+logs['width']]==' \U000f018d Logs ',labels
            assert labels[errors['col']:errors['col']+errors['width']]==' \U000f05d6 Errors 3 ',labels
            # The strip is the panel's surface, and the panel's first line stays visible.
            assert attr(top,width-2)!=attr(top-1,width-2),'bottom tabs share the editor background'
            assert 'bottom first line' in row(top+header_rows),row(top+header_rows)
            if args.underline:
                assert attr(top+1,logs['col']+3)!=attr(top+1,errors['col']+3),'bottom tab not lit'
            click(top-1,errors['col']+3)
            assert 'fakeerrors' in filetypes() and 'fakelogs' not in filetypes(),filetypes()
            check_bottom()
            assert row(top)[errors['col']+1]=='\U000f0028',row(top)
            if args.underline:
                click(top,logs['col']+3)
                assert 'fakelogs' in filetypes() and 'fakeerrors' not in filetypes(),filetypes()
            else:
                lua("require('hank-panels').open('logs')");settle()
            # ]b inside a bottom panel walks the bottom side only.
            lua("vim.api.nvim_set_current_win(require('hank-panels').window('bottom'))")
            assert lua(owner)=='logs'
            assert lua("return require('hank-panels').cycle(1)");settle()
            assert lua(owner)=='errors' and 'fakelogs' not in filetypes(),filetypes()
            # Beside a sidebar the strip still spans the bottom panel only.
            lua("require('hank-panels').open('tree')");settle()
            check_bottom();check_track()
            assert block_open() and len(ordinary_windows())==3
            lua("require('hank-panels').close('tree')");lua("require('hank-panels').close('errors')");settle()
            assert not strips() and not bottom_layout() and len(ordinary_windows())==1
            assert all(n.api.get_option_value('winbar',{'win':w})==(' ' if args.underline else '') for w in ordinary_windows())
            check_track()
            print('PASS: bottom panels: tabs over the separator, rail in the winbar, clicks, one panel at a time, ]b, next to a sidebar')
        # Narrow view, wide characters, literal percent signs and duplicate basenames.
        for name in ('a/shared.txt','b/shared.txt','目录/宽字符-very-long-name.txt','100%.txt'):
            b=n.api.create_buf(True,False)
            n.api.buf_set_name(b,str(Path(directory)/name))
            n.api.set_current_buf(b)
        n.ui_try_resize(60,12);settle()
        assert 'Error' not in n.command_output('messages'),n.command_output('messages')
        assert ' 100%.txt ' in row(1)[prefix_width:],row(1)
        assert len(row(2))==60
        if args.underline:assert attr(2,1)==track_attr
        check_track()
        n.ui_try_resize(120,32);settle()
        n.api.set_current_buf(buffers[-1]);settle()
        print('PASS: overflow, Unicode and statusline escaping')
        if lua('return _G.Snacks ~= nil'):
            lua('for _,b in ipairs(vim.api.nvim_list_bufs()) do if vim.bo[b].buftype=="" then vim.bo[b].buflisted=vim.tbl_contains(...,b) end end',buffers)
            lua('_G.hank_test_explorer=Snacks.picker.explorer(); vim.wait(300)');settle()
            def check_sidebar():
                left=lua('return vim.api.nvim_win_get_width(hank_test_explorer.layout.root.win)+1')
                position=lua('return vim.api.nvim_win_get_position(hank_test_explorer.input.win.win)')
                assert position==[header_rows,0],position
                assert 'Explorer' in row(header_rows+1)[:left],row(header_rows+1)
                assert tabs_col()==block_width+1 and row(1)[block_width]==' ',row(1)
                assert row(1)[panel_col('explorer')]=='\U000f024b',row(1)
                assert row(1)[block_width+1:].startswith(' flake.nix  Justfile '),row(1)
                check_track()
                assert 'first line is visible' in row(header_rows+1)[left:],row(header_rows+1)
                assert lua('local w=hank_test_explorer.list.win.win; return vim.api.nvim_win_get_position(w)[1]+vim.api.nvim_win_get_height(w)')==30
                assert len(ordinary_windows())==2
                return left
            # Buffer tabs start exactly where the file window does.
            assert check_sidebar()==block_width+1
            assert lua("return require('hank-panels').is_open('explorer')")
            lua('hank_test_explorer.layout:update()');settle()
            check_sidebar()
            for screenrow,col,expected in ((0,3,buffers[0]),(header_rows-1,14,buffers[1])):
                click(screenrow,tabs_col()+col)
                assert n.api.get_current_buf().number==expected
            lua('vim.api.nvim_win_set_width(hank_test_explorer.layout.root.win,40)');settle()
            assert check_sidebar()==41
            n.ui_try_resize(100,32);settle();check_sidebar()
            n.ui_try_resize(120,32);settle();check_sidebar()
            n.command('tabnew');settle()
            # A new tabpage has no sidebar, so its header has no block.
            assert not block_open() and row(1)[prefix_width:].startswith(' flake.nix'),row(1)
            n.command('tabclose');settle();check_sidebar()
            for expression in ('Snacks.picker.files()','Snacks.lazygit({configure=false,interactive=false})'):
                lua('_G.hank_test_float='+expression);settle()
                assert not lua('local x={} for _,w in ipairs(vim.api.nvim_list_wins()) do if vim.bo[vim.api.nvim_win_get_buf(w)].filetype=="snacks_win_backdrop" then x[#x+1]=w end end return next(x)~=nil')
                lua('hank_test_float:close()');settle()
                check_sidebar()
            if args.capture_explorer_json:capture(args.capture_explorer_json)
            lua('hank_test_explorer:close()');settle()
            assert row(1)[prefix_width:].startswith(' flake.nix')
            assert len(ordinary_windows())==1
            check_track()
            assert 'Error' not in n.command_output('messages'),n.command_output('messages')
            assert not block_open() and tabs_col()==prefix_width
            print('PASS: full-width header above Explorer, block while it is open, resize, tabpages, close, Picker and LazyGit')
            if lua("return package.loaded['hank-panels'] ~= nil and require('hank-panels').get('git') ~= nil"):
                is_open="return require('hank-panels').is_open(...)"
                assert not block_open()
                lua("require('hank-panels').open('explorer')");lua('vim.wait(300)');settle()
                assert lua(is_open,'explorer') and block_open()
                click(0,panel_col('git'));lua('vim.wait(300)');settle()
                assert lua(is_open,'git') and not lua(is_open,'explorer')
                assert tabs_col()==block_width+1 and row(1)[block_width+1:].startswith(' flake.nix'),row(1)
                if args.underline:
                    assert lua('return vim.wo[vim.fn.win_getid(1)].winbar')==' '
                click(0,panel_col('git'));settle()
                assert not lua(is_open,'git') and len(ordinary_windows())==1 and not block_open()
                assert 'Error' not in n.command_output('messages'),n.command_output('messages')
                print('PASS: configured panels switch Explorer and Git from the header')
                owner="local p=require('hank-panels').at() return p and p.id"
                editor_buf=n.api.get_current_buf().number
                lua("require('hank-panels').open('explorer')");lua('vim.wait(300)');settle()
                assert lua(owner)=='explorer',lua(owner)
                n.input(']b');lua('vim.wait(300)');settle()
                assert lua(owner)=='git' and not lua(is_open,'explorer'),(lua(owner),filetypes())
                n.input('[b');lua('vim.wait(300)');settle()
                assert lua(owner)=='explorer' and not lua(is_open,'git'),(lua(owner),filetypes())
                assert lua('local t={} for _,w in ipairs(vim.api.nvim_tabpage_list_wins(0)) do local b=vim.api.nvim_win_get_buf(w) if vim.bo[b].buftype=="" then t[#t+1]=b end end return t')==[editor_buf]
                lua("for _,w in ipairs(vim.api.nvim_tabpage_list_wins(0)) do if vim.api.nvim_win_get_config(w).relative=='' and vim.bo[vim.api.nvim_win_get_buf(w)].buftype=='' then vim.api.nvim_set_current_win(w) break end end");settle()
                assert lua(owner) is None
                n.input(']b');settle()
                assert n.api.get_current_buf().number!=editor_buf
                lua("require('hank-panels').close('explorer')");settle()
                assert len(ordinary_windows())==1
                assert 'Error' not in n.command_output('messages'),n.command_output('messages')
                print('PASS: ]b / [b cycle panels inside the sidebar and switch buffers elsewhere')
                n.input('<M-m>');lua('vim.wait(600)');settle()
                assert lua(is_open,'terminal') and lua(owner)=='terminal',filetypes()
                win,top,left,width=check_bottom()
                assert all(label in row(top) for label in ('Problems','Terminal','Quickfix')),row(top)
                assert n.api.win_get_height(win)==12
                n.input('<C-\\><C-n>');n.input(']b');lua('vim.wait(400)');settle()
                assert lua(is_open,'quickfix') and not lua(is_open,'terminal') and lua(owner)=='quickfix',filetypes()
                check_bottom()
                lua("require('hank-panels').open('problems')");lua('vim.wait(600)');settle()
                assert lua(is_open,'problems') and not lua(is_open,'quickfix'),filetypes()
                win,top,left,width=check_bottom()
                assert 'Problems' in row(top) and n.api.win_get_height(win)==12,row(top)
                lua("require('hank-panels').close('problems')");settle()
                assert not strips() and len(ordinary_windows())==1,filetypes()
                assert 'Error' not in n.command_output('messages'),n.command_output('messages')
                print('PASS: bottom panels: terminal from <M-m>, ]b to quickfix, problems picker, one shared strip')
        if args.capture_json:
            # Keep only the three demonstration buffers for a readable preview.
            lua('for _,b in ipairs(vim.api.nvim_list_bufs()) do if vim.bo[b].buftype=="" then vim.bo[b].buflisted=vim.tbl_contains(...,b) end end',buffers)
            settle()
            capture(args.capture_json)
        lua('for _,b in ipairs(vim.api.nvim_list_bufs()) do vim.bo[b].modified=false end')
        try:
            n.command('quit')
        except EOFError:
            print('PASS: :quit exits the last editor; the decorative float does not keep Nvim alive')
        else:
            raise AssertionError('decorative window prevented :quit')
finally:
    try:n.command('qa!')
    except (EOFError,OSError):pass
