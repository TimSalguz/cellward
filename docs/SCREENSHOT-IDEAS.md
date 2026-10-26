# Screenshot ideas (requested, not implemented)

- Freeze a captured frame **before** opening selection UI. Area/window selection
  must crop that immutable frame, not capture a later moment after interaction.
- Offer window-only capture, including a shortcut and optionally a frame button.
- Allow capture of client contents without Cellward's border, buttons or hover
  panel; distinguish client geometry from the decorated window and compositor
  shadows. Respect scale, transforms and multiple outputs.
- Avoid focus changes, hover reveals and shortcut effects changing the captured
  moment. A frame-button press can itself change hover/pressed state: define
  whether the pre-press frame or client-only image is used, rather than promise
  perfect timing without compositor support.
- Keep screenshot destinations explicit: file, the chosen container's active
  clipboard, or host export. Do not broadcast images to every clipboard or
  automatically add sensitive screenshots to history.
- Use the host's authorized capture/portal path; do not grant ordinary container
  applications unrestricted screen capture. Check fullscreen, overview and
  protected-content behaviour. A compositor-level freeze may need niri support;
  a frozen selection overlay alone does not freeze other applications.
