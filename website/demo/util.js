
// stops the bubble
function stopBubble (e) {
    if (e.stopPropagation)
        e.stopPropagation();
    if ("cancelBubble" in e)
        e.cancelBubble = true;
}

// stops the bubble, as well as the default action
function stopEvent (e) {
    stopBubble(e);
    if (e.preventDefault)
        e.preventDefault();
    if ("returnValue" in e)
        e.returnValue = false;
    return false;
}

function regEvent (target, evt, func) {
    if (! target) return;
    if (target.attachEvent)
        target.attachEvent("on"+evt, func);
    if (target.addEventListener)
        target.addEventListener(evt, func, false);
}
