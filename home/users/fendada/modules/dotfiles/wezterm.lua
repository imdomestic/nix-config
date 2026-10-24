local wezterm = require 'wezterm'
local appearence = require 'appearence'
local config = {}

if wezterm.config_builder then
  config = wezterm.config_builder()
end
config.text_background_opacity = 0.6
config.window_background_opacity = 0.7
config.macos_window_background_blur = 20

config.automatically_reload_config = true
config.audible_bell = 'Disabled'
config.check_for_updates = false
config.status_update_interval = 500

config.enable_tab_bar = true
config.hide_tab_bar_if_only_one_tab = true
config.use_fancy_tab_bar = false
config.tab_max_width = 40
config.tab_bar_at_bottom = false

config.scrollback_lines = 10000
config.enable_scroll_bar = false
config.window_close_confirmation = 'AlwaysPrompt'

local tab_bar_colors = {
  bar_bg = '#181926',
  active_bg = '#24273a',
  active_fg = '#cad3f5',
  active_accent = '#8aadf4',
  inactive_bg = '#181926',
  inactive_fg = '#8087a2',
  hover_bg = '#363a4f',
  hover_fg = '#cad3f5',
  separator = '#363a4f',
  new_tab_fg = '#a6da95',
}

config.colors = {
  tab_bar = {
    background = tab_bar_colors.bar_bg,
    active_tab = {
      bg_color = tab_bar_colors.active_bg,
      fg_color = tab_bar_colors.active_fg,
      intensity = 'Bold',
    },
    inactive_tab = {
      bg_color = tab_bar_colors.inactive_bg,
      fg_color = tab_bar_colors.inactive_fg,
    },
    inactive_tab_hover = {
      bg_color = tab_bar_colors.hover_bg,
      fg_color = tab_bar_colors.hover_fg,
    },
    new_tab = {
      bg_color = tab_bar_colors.bar_bg,
      fg_color = tab_bar_colors.new_tab_fg,
    },
    new_tab_hover = {
      bg_color = tab_bar_colors.hover_bg,
      fg_color = tab_bar_colors.hover_fg,
    },
  },
}

local function basename(path)
  return string.gsub(path or '', '(.*[/\\])(.*)', '%2')
end

local function clean_tab_title(title)
  title = (title or ''):gsub('^%s+', ''):gsub('%s+$', '')
  title = title:gsub('^%S+@%S+:%s*', '')
  title = title:gsub('^~/', '')
  title = basename(title)

  return title
end

local function tab_icon(tab, title)
  local process = basename(tab.active_pane.foreground_process_name):lower()
  local clean_title = (title or ''):lower()

  if process:find('nvim', 1, true) or process:find('vim', 1, true) or clean_title:find('nvim', 1, true) or clean_title:find('vim', 1, true) then
    return ''
  elseif process:find('ssh', 1, true) or clean_title:find('ssh', 1, true) then
    return '󰢹'
  elseif process:find('node', 1, true) or clean_title:find('node', 1, true) then
    return '󰎙'
  elseif process:find('python', 1, true) or clean_title:find('python', 1, true) then
    return ''
  elseif process:find('git', 1, true) or clean_title:find('git', 1, true) then
    return '󰊢'
  elseif process:find('zsh', 1, true) or process:find('bash', 1, true) or process:find('fish', 1, true) then
    return ''
  end

  return ''
end

wezterm.on('format-tab-title', function(tab, tabs, panes, config, hover, max_width)
  local colors = tab_bar_colors
  local bg = colors.inactive_bg
  local fg = colors.inactive_fg
  local accent = colors.inactive_fg
  local intensity = 'Normal'

  if tab.is_active then
    bg = colors.active_bg
    fg = colors.active_fg
    accent = colors.active_accent
    intensity = 'Bold'
  elseif hover then
    bg = colors.hover_bg
    fg = colors.hover_fg
    accent = colors.hover_fg
  end

  local title = tab.tab_title
  if title == '' then
    title = tab.active_pane.title
  end

  local index = tostring(tab.tab_index + 1)
  local title_max_width = math.max(8, max_width - 10)
  title = clean_tab_title(title)
  if title == '' then
    title = basename(tab.active_pane.foreground_process_name)
  end
  if title == '' then
    title = 'zsh'
  end
  title = wezterm.truncate_right(title, title_max_width)
  local icon = tab_icon(tab, title)

  return {
    { Background = { Color = bg } },
    { Foreground = { Color = accent } },
    { Attribute = { Intensity = intensity } },
    { Text = ' ' .. index .. ' ' .. icon .. ' ' },
    { Foreground = { Color = fg } },
    { Attribute = { Intensity = intensity } },
    { Text = title .. '  ' },
  }
end)

wezterm.on('update-status', function(window, pane)
  window:set_right_status('')
end)

config.font_dirs = {
  '/Users/a123456_1_2/Library/Fonts',
}

config.font = wezterm.font_with_fallback({
  "FiraCode Nerd Font",
  "Symbols Nerd Font",
  "Apple Color Emoji",
  "Heiti SC",
  "Hiragino Sans GB",
  "Songti SC",
  "Arial Unicode MS",
})

config.initial_cols = 150
config.initial_rows = 50

config.default_cursor_style = 'SteadyBar'

-- 让窗口可以是任意像素尺寸（别强行吸附到 cell 的整数倍）
config.use_resize_increments = false

-- 用 tiling WM 时建议关掉“改字体就改窗口像素尺寸”的行为
config.adjust_window_size_when_changing_font_size = false

config.window_decorations = "RESIZE"

-- config.enable_tab_bar = false
config.max_fps = 120

config.animation_fps = 120

config.keys = {
  -- Panes
  { key = 'phys:D',     mods = 'CMD|SHIFT', action = wezterm.action.SplitPane { direction = 'Right', size = { Percent = 50 } } },
  { key = 'phys:E',     mods = 'CMD|SHIFT', action = wezterm.action.SplitPane { direction = 'Down', size = { Percent = 50 } } },
  { key = 'phys:H',     mods = 'CMD|SHIFT', action = wezterm.action.ActivatePaneDirection 'Left' },
  { key = 'phys:J',     mods = 'CMD|SHIFT', action = wezterm.action.ActivatePaneDirection 'Down' },
  { key = 'phys:K',     mods = 'CMD|SHIFT', action = wezterm.action.ActivatePaneDirection 'Up' },
  { key = 'phys:L',     mods = 'CMD|SHIFT', action = wezterm.action.ActivatePaneDirection 'Right' },
  { key = 'LeftArrow',  mods = 'CMD|SHIFT', action = wezterm.action.AdjustPaneSize { 'Left', 5 } },
  { key = 'DownArrow',  mods = 'CMD|SHIFT', action = wezterm.action.AdjustPaneSize { 'Down', 5 } },
  { key = 'UpArrow',    mods = 'CMD|SHIFT', action = wezterm.action.AdjustPaneSize { 'Up', 5 } },
  { key = 'RightArrow', mods = 'CMD|SHIFT', action = wezterm.action.AdjustPaneSize { 'Right', 5 } },
  { key = 'phys:Z',     mods = 'CMD|SHIFT', action = wezterm.action.TogglePaneZoomState },
  { key = 'phys:X',     mods = 'CMD|SHIFT', action = wezterm.action.CloseCurrentPane { confirm = true } },

  -- Tabs
  { key = 'phys:T',     mods = 'CMD|SHIFT', action = wezterm.action.SpawnTab 'CurrentPaneDomain' },
  { key = ']',          mods = 'CMD|SHIFT', action = wezterm.action.ActivateTabRelative(1) },
  { key = '[',          mods = 'CMD|SHIFT', action = wezterm.action.ActivateTabRelative(-1) },
  { key = 'phys:W',     mods = 'CMD|SHIFT', action = wezterm.action.CloseCurrentTab { confirm = true } },

  -- Workspaces and launchers
  { key = 'phys:O',     mods = 'CMD|SHIFT', action = wezterm.action.ShowLauncherArgs { flags = 'WORKSPACES' } },
  { key = 'phys:P',     mods = 'CMD|SHIFT', action = wezterm.action.ShowLauncherArgs { flags = 'FUZZY|WORKSPACES' } },
  {
    key = 'phys:N',
    mods = 'CMD|SHIFT',
    action = wezterm.action.PromptInputLine {
      description = 'New workspace name',
      action = wezterm.action_callback(function(window, pane, line)
        if line then
          window:perform_action(wezterm.action.SwitchToWorkspace { name = line }, pane)
        end
      end),
    },
  },
}

config.window_padding = {
  left = 2,
  right = 2,
  top = 0,
  bottom = 2,
}
config.font_size = 15

config.color_scheme = 'catppuccin-macchiato' --'Catppuccin Frappe'
-- config.font = wezterm.font_with_fallback {
-- {
-- family = 'FiraCode Nerd Font Mono',
-- weight = 'Medium',
-- harfbuzz_features = { 'calt=0', 'clig=0', 'liga=0' },
-- },
-- { family = 'Terminus', weight = 'Bold' },
-- 'Noto Color Emoji',
-- }
--config.font = wezterm.font_with_fallback{
--family = "FiraCode Nerd Font Mono",
--weight = "Medium",
--harfbuzz_features = {"calt=0", "clig=0", "liga=0"},
--}

config.inactive_pane_hsb = {
  saturation = 0.9,
  brightness = 0.8,
}

return config
