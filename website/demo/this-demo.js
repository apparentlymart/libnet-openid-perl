var setupWin;

function onDebugButton () {
	alert("setupWin1 = " + setupWin);
	try {
		setupWin = window.open("about:blank", "user_setup_url_win");
        } catch (ex) { }
	alert("setupWin2 = " + setupWin);
	if (setupWin) {
	    setupWin.close();
	}
}

function cbSuccess (url, idserver, timestamp, sig) {
    makeGreen();
    setNote("Success!  You own <b>"+ehtml(url)+"</b>, asserted by " + ehtml(idserver) + " at " + ehtml(timestamp) + ", proof is " + ehtml(sig));


    var ex;

    // find the setup window, if they clicked the regular link
    if (! setupWin) {
	try {
		setupWin = window.open("about:blank", "user_setup_url_win");
        } catch (ex) { }
    }

    // and now try to close whatever it was
    try {
	    if (setupWin) 
		setupWin.close();
    } catch (ex) { }

    prepareWipeOnType();
}

function cbError (errcode, errtxt) {
    makeRed();
    setNote("<b>Error:</b> " + ehtml(errtxt) + "<br /><small><i>[" + ehtml(errcode) + "]</i></small>");

    prepareWipeOnType();

    var ue = document.getElementById('openid_url');
    ue.focus();
}

function ehtml (str) {
        if (!str) return "";
	return str.replace(/&/g, "&amp;").replace(/\"/g, "&quot;").replace(/\'/g, "&#39;").replace(/>/g, "&gt;").replace(/</g, "&lt;");
}

var setup_URL;

function popSetupURL () {
    setupWin = window.open(setup_URL, "user_setup_url_win");
    return false;
}

function cbNeedPermissions (url) {
    // FIXME: lookup javascript html escape function
    makeYellow();
    setup_URL = url;
    setNote("<b>Note:</b> You need to <a onclick='return popSetupURL();' target='user_setup_url_win' href='" + url + "'>grant permission</a> for this site to know who you are.  Once you do so, press Login again.");

    popSetupURL();
    prepareWipeOnType();
}

function cbDebug (txt) {
    // setNote("<b>Debug:</b><pre>" + txt + "</pre>");
}

function cbPostHelper (id, url) {
    setNote("Contacting identity server (" + ehtml(id) + ") to validate URL (" + ehtml(url) + ")");
    prepareWipeOnType();
}

function makeGray () {
    var be = document.getElementById('outerbox');
    be.style.background = '#ccc';
    be.style.border = '1px solid #999';
}

function makeYellow () {
    var be = document.getElementById('outerbox');
    be.style.background = '#FBFFC6';
    be.style.border = '1px solid #ECFF00';
}

function makeRed () {
    var be = document.getElementById('outerbox');
    be.style.background = '#FFA3A2';
    be.style.border = '1px solid #FF2523';
}

function makeGreen () {
    var be = document.getElementById('outerbox');
    be.style.background = '#CAFFC9';
    be.style.border = '1px solid #396CFF';
}


function onClickVerify (e) {
    if (!e) e = window.event;

    makeGray();
    var ue = document.getElementById('openid_url');
    if (!ue) return alert("assert: no ue");

    var client_url = ue.value;

	var opts = { 
	    'client_url': client_url,
	    'on_success': cbSuccess,
	    'on_error': cbError,
	    'on_debug': cbDebug,
	    'on_need_permissions': cbNeedPermissions,
	    'on_post_helper': cbPostHelper,
	    'post_grant': "close"
	    };

	if (location.host == 'openid.net' || location.host == 'www.openid.net') {
	    opts.trust_root = "http://*.openid.net/demo/";
	    opts.helper_url = "http://" + location.host + "/demo/helper.bml?host=" + location.host;
       } else {
	    opts.trust_root = "http://*.danga.com/openid/demo/";
	    opts.helper_url = "http://" + location.host + "/openid/demo/helper.bml?host=" + location.host;
       }

    OpenID_verify(opts);

    setNote("Contacting helper...");
    
    return stopEvent(e);
}

function setNote (txt) {
    var me = document.getElementById('msg');
    if (!me) return alert("assert: no me");
    me.innerHTML = txt;
}

function showExample () {
    setNote("<i>Example: <tt>brad.livejournal.com</tt></i>");
}

function introUI () {
    makeGray();
    showExample();
    removeWipeOnType();
}

function prepareWipeOnType () {
    var ue = document.getElementById('openid_url');
    ue.onkeydown = introUI;
    ue.onkeypress = introUI;
}

function removeWipeOnType () {
    var ue = document.getElementById('openid_url');
    ue.onkeydown = null;
    ue.onkeypress = null;
}

function onResetButton () {
    var ue = document.getElementById('openid_url');
    ue.value = "";
    ue.focus();
    introUI();
}

function initPage () {
    if (! document.getElementById || ! OpenID_capable()) {
	// alert("This demo won't work in your browser.");
    } else {
	var be = document.getElementById('verify_button');
	if (!be) return alert("assert: no be");
	regEvent(be, "click", onClickVerify);
	var fe = document.getElementById('demo_form');
	regEvent(fe, "submit", onClickVerify);

	var de = document.getElementById('debug_button');
	regEvent(de, "click", onDebugButton);

	var rb = document.getElementById('reset_button');
	rb.onclick = onResetButton;
	onResetButton();
    }
}

regEvent(window, "load", initPage);


