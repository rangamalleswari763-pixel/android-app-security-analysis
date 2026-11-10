Java.perform(function () {

    console.log("[+] Frida attached to DIVA");

    var Log = Java.use("android.util.Log");

    var logError = Log.e.overload(
        "java.lang.String",
        "java.lang.String"
    );

    logError.implementation = function (tag, message) {

        console.log("[LOG.e] Tag: " + tag);
        console.log("[LOG.e] Message: " + message);

        return logError.call(this, tag, message);
    };

    console.log("[+] android.util.Log.e() hook installed");
});