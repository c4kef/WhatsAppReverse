// Подключаемся к процессу WhatsApp

Java.perform(async function() {
    var RootPackages = ["com.noshufou.android.su", "com.noshufou.android.su.elite", "eu.chainfire.supersu",
        "com.koushikdutta.superuser", "com.thirdparty.superuser", "com.yellowes.su", "com.koushikdutta.rommanager",
        "com.koushikdutta.rommanager.license", "com.dimonvideo.luckypatcher", "com.chelpus.lackypatch",
        "com.ramdroid.appquarantine", "com.ramdroid.appquarantinepro", "com.devadvance.rootcloak", "com.devadvance.rootcloakplus",
        "de.robv.android.xposed.installer", "com.saurik.substrate", "com.zachspong.temprootremovejb", "com.amphoras.hidemyroot",
        "com.amphoras.hidemyrootadfree", "com.formyhm.hiderootPremium", "com.formyhm.hideroot", "me.phh.superuser",
        "eu.chainfire.supersu.pro", "com.kingouser.com", "com.topjohnwu.magisk"
    ];

    var RootBinaries = ["su", "busybox", "supersu", "Superuser.apk", "KingoUser.apk", "SuperSu.apk", "magisk"];

    var RootProperties = {
        "ro.build.selinux": "1",
        "ro.debuggable": "0",
        "service.adb.root": "0",
        "ro.secure": "1"
    };

    var RootPropertiesKeys = [];

    for (var k in RootProperties) RootPropertiesKeys.push(k);

    var PackageManager = Java.use("android.app.ApplicationPackageManager");

    var Runtime = Java.use('java.lang.Runtime');

    var NativeFile = Java.use('java.io.File');

    var String = Java.use('java.lang.String');

    var SystemProperties = Java.use('android.os.SystemProperties');

    var BufferedReader = Java.use('java.io.BufferedReader');

    var ProcessBuilder = Java.use('java.lang.ProcessBuilder');

    var StringBuffer = Java.use('java.lang.StringBuffer');

    var loaded_classes = Java.enumerateLoadedClassesSync();

    send("Loaded " + loaded_classes.length + " classes!");

    var useKeyInfo = false;

    var useProcessManager = false;

    send("loaded: " + loaded_classes.indexOf('java.lang.ProcessManager'));

    if (loaded_classes.indexOf('java.lang.ProcessManager') != -1) {
        try {
            //useProcessManager = true;
            //var ProcessManager = Java.use('java.lang.ProcessManager');
        } catch (err) {
            send("ProcessManager Hook failed: " + err);
        }
    } else {
        send("ProcessManager hook not loaded");
    }

    var KeyInfo = null;

    if (loaded_classes.indexOf('android.security.keystore.KeyInfo') != -1) {
        try {
            //useKeyInfo = true;
            //var KeyInfo = Java.use('android.security.keystore.KeyInfo');
        } catch (err) {
            send("KeyInfo Hook failed: " + err);
        }
    } else {
        send("KeyInfo hook not loaded");
    }

    PackageManager.getPackageInfo.overload('java.lang.String', 'int').implementation = function(pname, flags) {
        var shouldFakePackage = (RootPackages.indexOf(pname) > -1);
        if (shouldFakePackage) {
            send("Bypass root check for package: " + pname);
            pname = "set.package.name.to.a.fake.one.so.we.can.bypass.it";
        }
        return this.getPackageInfo.overload('java.lang.String', 'int').call(this, pname, flags);
    };

    NativeFile.exists.implementation = function() {
        var name = NativeFile.getName.call(this);
        var shouldFakeReturn = (RootBinaries.indexOf(name) > -1);
        if (shouldFakeReturn) {
            send("Bypass return value for binary: " + name);
            return false;
        } else {
            return this.exists.call(this);
        }
    };

    var exec = Runtime.exec.overload('[Ljava.lang.String;');
    var exec1 = Runtime.exec.overload('java.lang.String');
    var exec2 = Runtime.exec.overload('java.lang.String', '[Ljava.lang.String;');
    var exec3 = Runtime.exec.overload('[Ljava.lang.String;', '[Ljava.lang.String;');
    var exec4 = Runtime.exec.overload('[Ljava.lang.String;', '[Ljava.lang.String;', 'java.io.File');
    var exec5 = Runtime.exec.overload('java.lang.String', '[Ljava.lang.String;', 'java.io.File');

    exec5.implementation = function(cmd, env, dir) {
        if (cmd.indexOf("getprop") != -1 || cmd == "mount" || cmd.indexOf("build.prop") != -1 || cmd == "id" || cmd == "sh") {
            var fakeCmd = "grep";
            send("Bypass " + cmd + " command");
            return exec1.call(this, fakeCmd);
        }
        if (cmd == "su") {
            var fakeCmd = "justafakecommandthatcannotexistsusingthisshouldthowanexceptionwheneversuiscalled";
            send("Bypass " + cmd + " command");
            return exec1.call(this, fakeCmd);
        }
        return exec5.call(this, cmd, env, dir);
    };

    exec4.implementation = function(cmdarr, env, file) {
        for (var i = 0; i < cmdarr.length; i = i + 1) {
            var tmp_cmd = cmdarr[i];
            if (tmp_cmd.indexOf("getprop") != -1 || tmp_cmd == "mount" || tmp_cmd.indexOf("build.prop") != -1 || tmp_cmd == "id" || tmp_cmd == "sh") {
                var fakeCmd = "grep";
                send("Bypass " + cmdarr + " command");
                return exec1.call(this, fakeCmd);
            }

            if (tmp_cmd == "su") {
                var fakeCmd = "justafakecommandthatcannotexistsusingthisshouldthowanexceptionwheneversuiscalled";
                send("Bypass " + cmdarr + " command");
                return exec1.call(this, fakeCmd);
            }
        }
        return exec4.call(this, cmdarr, env, file);
    };

    exec3.implementation = function(cmdarr, envp) {
        for (var i = 0; i < cmdarr.length; i = i + 1) {
            var tmp_cmd = cmdarr[i];
            if (tmp_cmd.indexOf("getprop") != -1 || tmp_cmd == "mount" || tmp_cmd.indexOf("build.prop") != -1 || tmp_cmd == "id" || tmp_cmd == "sh") {
                var fakeCmd = "grep";
                send("Bypass " + cmdarr + " command");
                return exec1.call(this, fakeCmd);
            }

            if (tmp_cmd == "su") {
                var fakeCmd = "justafakecommandthatcannotexistsusingthisshouldthowanexceptionwheneversuiscalled";
                send("Bypass " + cmdarr + " command");
                return exec1.call(this, fakeCmd);
            }
        }
        return exec3.call(this, cmdarr, envp);
    };

    exec2.implementation = function(cmd, env) {
        if (cmd.indexOf("getprop") != -1 || cmd == "mount" || cmd.indexOf("build.prop") != -1 || cmd == "id" || cmd == "sh") {
            var fakeCmd = "grep";
            send("Bypass " + cmd + " command");
            return exec1.call(this, fakeCmd);
        }
        if (cmd == "su") {
            var fakeCmd = "justafakecommandthatcannotexistsusingthisshouldthowanexceptionwheneversuiscalled";
            send("Bypass " + cmd + " command");
            return exec1.call(this, fakeCmd);
        }
        return exec2.call(this, cmd, env);
    };

    exec.implementation = function(cmd) {
        for (var i = 0; i < cmd.length; i = i + 1) {
            var tmp_cmd = cmd[i];
            if (tmp_cmd.indexOf("getprop") != -1 || tmp_cmd == "mount" || tmp_cmd.indexOf("build.prop") != -1 || tmp_cmd == "id" || tmp_cmd == "sh") {
                var fakeCmd = "grep";
                send("Bypass " + cmd + " command");
                return exec1.call(this, fakeCmd);
            }

            if (tmp_cmd == "su") {
                var fakeCmd = "justafakecommandthatcannotexistsusingthisshouldthowanexceptionwheneversuiscalled";
                send("Bypass " + cmd + " command");
                return exec1.call(this, fakeCmd);
            }
        }

        return exec.call(this, cmd);
    };

    exec1.implementation = function(cmd) {
        if (cmd.indexOf("getprop") != -1 || cmd == "mount" || cmd.indexOf("build.prop") != -1 || cmd == "id" || cmd == "sh") {
            var fakeCmd = "grep";
            send("Bypass " + cmd + " command");
            return exec1.call(this, fakeCmd);
        }
        if (cmd == "su") {
            var fakeCmd = "justafakecommandthatcannotexistsusingthisshouldthowanexceptionwheneversuiscalled";
            send("Bypass " + cmd + " command");
            return exec1.call(this, fakeCmd);
        }
        return exec1.call(this, cmd);
    };

    String.contains.implementation = function(name) {
        if (name == "test-keys") {
            send("Bypass test-keys check");
            return false;
        }
        return this.contains.call(this, name);
    };

    var get = SystemProperties.get.overload('java.lang.String');

    get.implementation = function(name) {
        if (RootPropertiesKeys.indexOf(name) != -1) {
            send("Bypass " + name);
            return RootProperties[name];
        }
        return this.get.call(this, name);
    };

    Interceptor.attach(Module.findExportByName("libc.so", "fopen"), {
        onEnter: function(args) {
            var path = Memory.readCString(args[0]);
            path = path.split("/");
            var executable = path[path.length - 1];
            var shouldFakeReturn = (RootBinaries.indexOf(executable) > -1)
            if (shouldFakeReturn) {
                Memory.writeUtf8String(args[0], "/notexists");
                send("Bypass native fopen");
            }
        },
        onLeave: function(retval) {

        }
    });

    Interceptor.attach(Module.findExportByName("libc.so", "system"), {
        onEnter: function(args) {
            var cmd = Memory.readCString(args[0]);
            send("SYSTEM CMD: " + cmd);
            if (cmd.indexOf("getprop") != -1 || cmd == "mount" || cmd.indexOf("build.prop") != -1 || cmd == "id") {
                send("Bypass native system: " + cmd);
                Memory.writeUtf8String(args[0], "grep");
            }
            if (cmd == "su") {
                send("Bypass native system: " + cmd);
                Memory.writeUtf8String(args[0], "justafakecommandthatcannotexistsusingthisshouldthowanexceptionwheneversuiscalled");
            }
        },
        onLeave: function(retval) {

        }
    });


    setTimeout(function() {
        Java.perform(function() {
            console.log('');
            console.log('======');
            console.log('[#] Android Bypass for various Certificate Pinning methods [#]');
            console.log('======');
            
            var errDict = {};
    
            // TrustManager (Android < 7) //
            ////////////////////////////////
            var X509TrustManager = Java.use('javax.net.ssl.X509TrustManager');
            var SSLContext = Java.use('javax.net.ssl.SSLContext');
            var TrustManager = Java.registerClass({
                // Implement a custom TrustManager
                name: 'dev.asd.test.TrustManager',
                implements: [X509TrustManager],
                methods: {
                    checkClientTrusted: function(chain, authType) {},
                    checkServerTrusted: function(chain, authType) {},
                    getAcceptedIssuers: function() {return []; }
                }
            });
            // Prepare the TrustManager array to pass to SSLContext.init()
            var TrustManagers = [TrustManager.$new()];
            // Get a handle on the init() on the SSLContext class
            var SSLContext_init = SSLContext.init.overload(
                '[Ljavax.net.ssl.KeyManager;', '[Ljavax.net.ssl.TrustManager;', 'java.security.SecureRandom');
            try {
                // Override the init method, specifying the custom TrustManager
                SSLContext_init.implementation = function(keyManager, trustManager, secureRandom) {
                    console.log('[+] Bypassing Trustmanager (Android < 7) pinner');
                    SSLContext_init.call(this, keyManager, TrustManagers, secureRandom);
                };
            } catch (err) {
                console.log('[-] TrustManager (Android < 7) pinner not found');
                //console.log(err);
            }
    
    
    
        
            // OkHTTPv3 (quadruple bypass) //
            /////////////////////////////////
            try {
                // Bypass OkHTTPv3 {1}
                var okhttp3_Activity_1 = Java.use('okhttp3.CertificatePinner');
                okhttp3_Activity_1.check.overload('java.lang.String', 'java.util.List').implementation = function(a, b) {
                    console.log('[+] Bypassing OkHTTPv3 {1}: ' + a);
                    return;
                };
            } catch (err) {
                console.log('[-] OkHTTPv3 {1} pinner not found');
                //console.log(err);
                errDict[err] = ['okhttp3.CertificatePinner', 'check'];
            }
            try {
                // Bypass OkHTTPv3 {2}
                // This method of CertificatePinner.check is deprecated but could be found in some old Android apps
                var okhttp3_Activity_2 = Java.use('okhttp3.CertificatePinner');
                okhttp3_Activity_2.check.overload('java.lang.String', 'java.security.cert.Certificate').implementation = function(a, b) {
                    console.log('[+] Bypassing OkHTTPv3 {2}: ' + a);
                    return;
                };
            } catch (err) {
                console.log('[-] OkHTTPv3 {2} pinner not found');
                //console.log(err);
                //errDict[err] = ['okhttp3.CertificatePinner', 'check'];
            }
            try {
                // Bypass OkHTTPv3 {3}
                var okhttp3_Activity_3 = Java.use('okhttp3.CertificatePinner');
                okhttp3_Activity_3.check.overload('java.lang.String', '[Ljava.security.cert.Certificate;').implementation = function(a, b) {
                    console.log('[+] Bypassing OkHTTPv3 {3}: ' + a);
                    return;
                };
            } catch(err) {
                console.log('[-] OkHTTPv3 {3} pinner not found');
                //console.log(err);
                errDict[err] = ['okhttp3.CertificatePinner', 'check'];
            }
            try {
                // Bypass OkHTTPv3 {4}
                var okhttp3_Activity_4 = Java.use('okhttp3.CertificatePinner'); 
                //okhttp3_Activity_4['check$okhttp'].implementation = function(a, b) {
                okhttp3_Activity_4.check$okhttp.overload('java.lang.String', 'kotlin.jvm.functions.Function0').implementation = function(a, b) {		
                    console.log('[+] Bypassing OkHTTPv3 {4}: ' + a);
                    return;
                };
            } catch(err) {
                console.log('[-] OkHTTPv3 {4} pinner not found');
                //console.log(err);
                errDict[err] = ['okhttp3.CertificatePinner', 'check$okhttp'];
            }
        
    
        
            // Trustkit (triple bypass) //
            //////////////////////////////
            try {
                // Bypass Trustkit {1}
                var trustkit_Activity_1 = Java.use('com.datatheorem.android.trustkit.pinning.OkHostnameVerifier');
                trustkit_Activity_1.verify.overload('java.lang.String', 'javax.net.ssl.SSLSession').implementation = function(a, b) {
                    console.log('[+] Bypassing Trustkit {1}: ' + a);
                    return true;
                };
            } catch (err) {
                console.log('[-] Trustkit {1} pinner not found');
                //console.log(err);
                errDict[err] = ['com.datatheorem.android.trustkit.pinning.OkHostnameVerifier', 'verify'];
            }
            try {
                // Bypass Trustkit {2}
                var trustkit_Activity_2 = Java.use('com.datatheorem.android.trustkit.pinning.OkHostnameVerifier');
                trustkit_Activity_2.verify.overload('java.lang.String', 'java.security.cert.X509Certificate').implementation = function(a, b) {
                    console.log('[+] Bypassing Trustkit {2}: ' + a);
                    return true;
                };
            } catch (err) {
                console.log('[-] Trustkit {2} pinner not found');
                //console.log(err);
                errDict[err] = ['com.datatheorem.android.trustkit.pinning.OkHostnameVerifier', 'verify'];
            }
            try {
                // Bypass Trustkit {3}
                var trustkit_PinningTrustManager = Java.use('com.datatheorem.android.trustkit.pinning.PinningTrustManager');
                trustkit_PinningTrustManager.checkServerTrusted.overload('[Ljava.security.cert.X509Certificate;', 'java.lang.String').implementation = function(chain, authType) {
                    console.log('[+] Bypassing Trustkit {3}');
                };
            } catch (err) {
                console.log('[-] Trustkit {3} pinner not found');
                //console.log(err);
                errDict[err] = ['com.datatheorem.android.trustkit.pinning.PinningTrustManager', 'checkServerTrusted'];
            }
            
        
        
      
            // TrustManagerImpl (Android > 7) //
            ////////////////////////////////////
            try {
                // Bypass TrustManagerImpl (Android > 7) {1}
                var array_list = Java.use("java.util.ArrayList");
                var TrustManagerImpl_Activity_1 = Java.use('com.android.org.conscrypt.TrustManagerImpl');
                TrustManagerImpl_Activity_1.checkTrustedRecursive.implementation = function(certs, ocspData, tlsSctData, host, clientAuth, untrustedChain, trustAnchorChain, used) {
                    console.log('[+] Bypassing TrustManagerImpl (Android > 7) checkTrustedRecursive check for: '+ host);
                    return array_list.$new();
                };
            } catch (err) {
                console.log('[-] TrustManagerImpl (Android > 7) checkTrustedRecursive check not found');
                //console.log(err);
                errDict[err] = ['com.android.org.conscrypt.TrustManagerImpl', 'checkTrustedRecursive'];
            }  
            try {
                // Bypass TrustManagerImpl (Android > 7) {2} (probably no more necessary)
                var TrustManagerImpl_Activity_2 = Java.use('com.android.org.conscrypt.TrustManagerImpl');
                TrustManagerImpl_Activity_2.verifyChain.implementation = function(untrustedChain, trustAnchorChain, host, clientAuth, ocspData, tlsSctData) {
                    console.log('[+] Bypassing TrustManagerImpl (Android > 7) verifyChain check for: ' + host);
                    return untrustedChain;
                };   
            } catch (err) {
                console.log('[-] TrustManagerImpl (Android > 7) verifyChain check not found');
                //console.log(err);
                errDict[err] = ['com.android.org.conscrypt.TrustManagerImpl', 'verifyChain'];  
            }
    
      
      
            
    
            // Appcelerator Titanium PinningTrustManager //
            ///////////////////////////////////////////////
            try {
                var appcelerator_PinningTrustManager = Java.use('appcelerator.https.PinningTrustManager');
                appcelerator_PinningTrustManager.checkServerTrusted.implementation = function(chain, authType) {
                    console.log('[+] Bypassing Appcelerator PinningTrustManager');
                    return;
                };
            } catch (err) {
                console.log('[-] Appcelerator PinningTrustManager pinner not found');
                //console.log(err);
                errDict[err] = ['appcelerator.https.PinningTrustManager', 'checkServerTrusted'];  
            }
    
    
    
    
            // Fabric PinningTrustManager //
            ////////////////////////////////
            try {
                var fabric_PinningTrustManager = Java.use('io.fabric.sdk.android.services.network.PinningTrustManager');
                fabric_PinningTrustManager.checkServerTrusted.implementation = function(chain, authType) {
                    console.log('[+] Bypassing Fabric PinningTrustManager');
                    return;
                };
            } catch (err) {
                console.log('[-] Fabric PinningTrustManager pinner not found');
                //console.log(err);
                errDict[err] = ['io.fabric.sdk.android.services.network.PinningTrustManager', 'checkServerTrusted'];  
            }
    
    
    
    
            // OpenSSLSocketImpl Conscrypt (double bypass) //
            /////////////////////////////////////////////////
            try {
                var OpenSSLSocketImpl = Java.use('com.android.org.conscrypt.OpenSSLSocketImpl');
                OpenSSLSocketImpl.verifyCertificateChain.implementation = function(certRefs, JavaObject, authMethod) {
                    console.log('[+] Bypassing OpenSSLSocketImpl Conscrypt {1}');
                };
            } catch (err) {
                console.log('[-] OpenSSLSocketImpl Conscrypt {1} pinner not found');
                //console.log(err);
                errDict[err] = ['com.android.org.conscrypt.OpenSSLSocketImpl', 'verifyCertificateChain'];
            }
            try {
                var OpenSSLSocketImpl = Java.use('com.android.org.conscrypt.OpenSSLSocketImpl');
                OpenSSLSocketImpl.verifyCertificateChain.implementation = function(certChain, authMethod) {
                    console.log('[+] Bypassing OpenSSLSocketImpl Conscrypt {2}');
                };
            } catch (err) {
                console.log('[-] OpenSSLSocketImpl Conscrypt {2} pinner not found');
                //console.log(err);
                errDict[err] = ['com.android.org.conscrypt.OpenSSLSocketImpl', 'verifyCertificateChain'];  
            }
    
    
    
    
            // OpenSSLEngineSocketImpl Conscrypt //
            ///////////////////////////////////////
            try {
                var OpenSSLEngineSocketImpl_Activity = Java.use('com.android.org.conscrypt.OpenSSLEngineSocketImpl');
                OpenSSLEngineSocketImpl_Activity.verifyCertificateChain.overload('[Ljava.lang.Long;', 'java.lang.String').implementation = function(a, b) {
                    console.log('[+] Bypassing OpenSSLEngineSocketImpl Conscrypt: ' + b);
                };
            } catch (err) {
                console.log('[-] OpenSSLEngineSocketImpl Conscrypt pinner not found');
                //console.log(err);
                errDict[err] = ['com.android.org.conscrypt.OpenSSLEngineSocketImpl', 'verifyCertificateChain'];
            }
    
    
    
    
            // OpenSSLSocketImpl Apache Harmony //
            //////////////////////////////////////
            try {
                var OpenSSLSocketImpl_Harmony = Java.use('org.apache.harmony.xnet.provider.jsse.OpenSSLSocketImpl');
                OpenSSLSocketImpl_Harmony.verifyCertificateChain.implementation = function(asn1DerEncodedCertificateChain, authMethod) {
                    console.log('[+] Bypassing OpenSSLSocketImpl Apache Harmony');
                };
            } catch (err) {
                console.log('[-] OpenSSLSocketImpl Apache Harmony pinner not found');
                //console.log(err);
                errDict[err] = ['org.apache.harmony.xnet.provider.jsse.OpenSSLSocketImpl', 'verifyCertificateChain'];   
            }
    
    
    
    
            // PhoneGap sslCertificateChecker //
            ////////////////////////////////////
            try {
                var phonegap_Activity = Java.use('nl.xservices.plugins.sslCertificateChecker');
                phonegap_Activity.execute.overload('java.lang.String', 'org.json.JSONArray', 'org.apache.cordova.CallbackContext').implementation = function(a, b, c) {
                    console.log('[+] Bypassing PhoneGap sslCertificateChecker: ' + a);
                    return true;
                };
            } catch (err) {
                console.log('[-] PhoneGap sslCertificateChecker pinner not found');
                //console.log(err);
                errDict[err] = ['nl.xservices.plugins.sslCertificateChecker', 'execute'];
            }
    
    
    
    
            // IBM MobileFirst pinTrustedCertificatePublicKey (double bypass) //
            ////////////////////////////////////////////////////////////////////
            try {
                // Bypass IBM MobileFirst {1}
                var WLClient_Activity_1 = Java.use('com.worklight.wlclient.api.WLClient');
                WLClient_Activity_1.getInstance().pinTrustedCertificatePublicKey.overload('java.lang.String').implementation = function(cert) {
                    console.log('[+] Bypassing IBM MobileFirst pinTrustedCertificatePublicKey {1}: ' + cert);
                    return;
                };
                } catch (err) {
                console.log('[-] IBM MobileFirst pinTrustedCertificatePublicKey {1} pinner not found');
                //console.log(err);
                errDict[err] = ['com.worklight.wlclient.api.WLClient', 'pinTrustedCertificatePublicKey'];
            }
            try {
                // Bypass IBM MobileFirst {2}
                var WLClient_Activity_2 = Java.use('com.worklight.wlclient.api.WLClient');
                WLClient_Activity_2.getInstance().pinTrustedCertificatePublicKey.overload('[Ljava.lang.String;').implementation = function(cert) {
                    console.log('[+] Bypassing IBM MobileFirst pinTrustedCertificatePublicKey {2}: ' + cert);
                    return;
                };
            } catch (err) {
                console.log('[-] IBM MobileFirst pinTrustedCertificatePublicKey {2} pinner not found');
                //console.log(err);
                errDict[err] = ['com.worklight.wlclient.api.WLClient', 'pinTrustedCertificatePublicKey'];
            }
    
    
    
    
            // IBM WorkLight (ancestor of MobileFirst) HostNameVerifierWithCertificatePinning (quadruple bypass) //
            ///////////////////////////////////////////////////////////////////////////////////////////////////////
            try {
                // Bypass IBM WorkLight {1}
                var worklight_Activity_1 = Java.use('com.worklight.wlclient.certificatepinning.HostNameVerifierWithCertificatePinning');
                worklight_Activity_1.verify.overload('java.lang.String', 'javax.net.ssl.SSLSocket').implementation = function(a, b) {
                    console.log('[+] Bypassing IBM WorkLight HostNameVerifierWithCertificatePinning {1}: ' + a);
                    return;
                };
            } catch (err) {
                console.log('[-] IBM WorkLight HostNameVerifierWithCertificatePinning {1} pinner not found');
                //console.log(err);
                errDict[err] = ['com.worklight.wlclient.certificatepinning.HostNameVerifierWithCertificatePinning', 'verify'];
            }
            try {
                // Bypass IBM WorkLight {2}
                var worklight_Activity_2 = Java.use('com.worklight.wlclient.certificatepinning.HostNameVerifierWithCertificatePinning');
                worklight_Activity_2.verify.overload('java.lang.String', 'java.security.cert.X509Certificate').implementation = function(a, b) {
                    console.log('[+] Bypassing IBM WorkLight HostNameVerifierWithCertificatePinning {2}: ' + a);
                    return;
                };
            } catch (err) {
                console.log('[-] IBM WorkLight HostNameVerifierWithCertificatePinning {2} pinner not found');
                //console.log(err);
                errDict[err] = ['com.worklight.wlclient.certificatepinning.HostNameVerifierWithCertificatePinning', 'verify'];
            }
            try {
                // Bypass IBM WorkLight {3}
                var worklight_Activity_3 = Java.use('com.worklight.wlclient.certificatepinning.HostNameVerifierWithCertificatePinning');
                worklight_Activity_3.verify.overload('java.lang.String', '[Ljava.lang.String;', '[Ljava.lang.String;').implementation = function(a, b) {
                    console.log('[+] Bypassing IBM WorkLight HostNameVerifierWithCertificatePinning {3}: ' + a);
                    return;
                };
            } catch (err) {
                console.log('[-] IBM WorkLight HostNameVerifierWithCertificatePinning {3} pinner not found');
                //console.log(err);
                errDict[err] = ['com.worklight.wlclient.certificatepinning.HostNameVerifierWithCertificatePinning', 'verify'];
            }
            try {
                // Bypass IBM WorkLight {4}
                var worklight_Activity_4 = Java.use('com.worklight.wlclient.certificatepinning.HostNameVerifierWithCertificatePinning');
                worklight_Activity_4.verify.overload('java.lang.String', 'javax.net.ssl.SSLSession').implementation = function(a, b) {
                    console.log('[+] Bypassing IBM WorkLight HostNameVerifierWithCertificatePinning {4}: ' + a);
                    return true;
                };
            } catch (err) {
                console.log('[-] IBM WorkLight HostNameVerifierWithCertificatePinning {4} pinner not found');
                //console.log(err);
                errDict[err] = ['com.worklight.wlclient.certificatepinning.HostNameVerifierWithCertificatePinning', 'verify'];
            }
    
    
    
    
            // Conscrypt CertPinManager //
            //////////////////////////////
            try {
                var conscrypt_CertPinManager_Activity = Java.use('com.android.org.conscrypt.CertPinManager');
                conscrypt_CertPinManager_Activity.checkChainPinning.overload('java.lang.String', 'java.util.List').implementation = function(a, b) {
                    console.log('[+] Bypassing Conscrypt CertPinManager: ' + a);
                    return;
                };
            } catch (err) {
                console.log('[-] Conscrypt CertPinManager pinner not found');
                //console.log(err);
                errDict[err] = ['com.android.org.conscrypt.CertPinManager', 'checkChainPinning'];
            }
            
            
    
    
            // Conscrypt CertPinManager (Legacy) //
            ///////////////////////////////////////
            try {
                var legacy_conscrypt_CertPinManager_Activity = Java.use('com.android.org.conscrypt.CertPinManager');
                legacy_conscrypt_CertPinManager_Activity.isChainValid.overload('java.lang.String', 'java.util.List').implementation = function(a, b) {
                    console.log('[+] Bypassing Conscrypt CertPinManager (Legacy): ' + a);
                    return true;
                };
            } catch (err) {
                console.log('[-] Conscrypt CertPinManager (Legacy) pinner not found');
                //console.log(err);
                errDict[err] = ['com.android.org.conscrypt.CertPinManager', 'isChainValid'];
            }
               
                   
    
    
            // CWAC-Netsecurity (unofficial back-port pinner for Android<4.2) CertPinManager //
            ///////////////////////////////////////////////////////////////////////////////////
            try {
                var cwac_CertPinManager_Activity = Java.use('com.commonsware.cwac.netsecurity.conscrypt.CertPinManager');
                cwac_CertPinManager_Activity.isChainValid.overload('java.lang.String', 'java.util.List').implementation = function(a, b) {
                    console.log('[+] Bypassing CWAC-Netsecurity CertPinManager: ' + a);
                    return true;
                };
            } catch (err) {
                console.log('[-] CWAC-Netsecurity CertPinManager pinner not found');
                //console.log(err);
                errDict[err] = ['com.commonsware.cwac.netsecurity.conscrypt.CertPinManager', 'isChainValid'];
            }
    
    
    
    
            // Worklight Androidgap WLCertificatePinningPlugin //
            /////////////////////////////////////////////////////
            try {
                var androidgap_WLCertificatePinningPlugin_Activity = Java.use('com.worklight.androidgap.plugin.WLCertificatePinningPlugin');
                androidgap_WLCertificatePinningPlugin_Activity.execute.overload('java.lang.String', 'org.json.JSONArray', 'org.apache.cordova.CallbackContext').implementation = function(a, b, c) {
                    console.log('[+] Bypassing Worklight Androidgap WLCertificatePinningPlugin: ' + a);
                    return true;
                };
            } catch (err) {
                console.log('[-] Worklight Androidgap WLCertificatePinningPlugin pinner not found');
                //console.log(err);
                errDict[err] = ['com.worklight.androidgap.plugin.WLCertificatePinningPlugin', 'execute'];
            }
    
    
    
    
            // Netty FingerprintTrustManagerFactory //
            //////////////////////////////////////////
            try {
                var netty_FingerprintTrustManagerFactory = Java.use('io.netty.handler.ssl.util.FingerprintTrustManagerFactory');
                //NOTE: sometimes this below implementation could be useful 
                //var netty_FingerprintTrustManagerFactory = Java.use('org.jboss.netty.handler.ssl.util.FingerprintTrustManagerFactory');
                netty_FingerprintTrustManagerFactory.checkTrusted.implementation = function(type, chain) {
                    console.log('[+] Bypassing Netty FingerprintTrustManagerFactory');
                };
            } catch (err) {
                console.log('[-] Netty FingerprintTrustManagerFactory pinner not found');
                //console.log(err);
                errDict[err] = ['io.netty.handler.ssl.util.FingerprintTrustManagerFactory', 'checkTrusted'];
            }
    
    
    
    
            // Squareup CertificatePinner [OkHTTP<v3] (double bypass) //
            ////////////////////////////////////////////////////////////
            try {
                // Bypass Squareup CertificatePinner  {1}
                var Squareup_CertificatePinner_Activity_1 = Java.use('com.squareup.okhttp.CertificatePinner');
                Squareup_CertificatePinner_Activity_1.check.overload('java.lang.String', 'java.security.cert.Certificate').implementation = function(a, b) {
                    console.log('[+] Bypassing Squareup CertificatePinner {1}: ' + a);
                    return;
                };
            } catch (err) {
                console.log('[-] Squareup CertificatePinner {1} pinner not found');
                //console.log(err);
                errDict[err] = ['com.squareup.okhttp.CertificatePinner', 'check'];
            }
            try {
                // Bypass Squareup CertificatePinner {2}
                var Squareup_CertificatePinner_Activity_2 = Java.use('com.squareup.okhttp.CertificatePinner');
                Squareup_CertificatePinner_Activity_2.check.overload('java.lang.String', 'java.util.List').implementation = function(a, b) {
                    console.log('[+] Bypassing Squareup CertificatePinner {2}: ' + a);
                    return;
                };
            } catch (err) {
                console.log('[-] Squareup CertificatePinner {2} pinner not found');
                //console.log(err);
                errDict[err] = ['com.squareup.okhttp.CertificatePinner', 'check'];
            }
    
    
    
    
            // Squareup OkHostnameVerifier [OkHTTP v3] (double bypass) //
            /////////////////////////////////////////////////////////////
            try {
                // Bypass Squareup OkHostnameVerifier {1}
                var Squareup_OkHostnameVerifier_Activity_1 = Java.use('com.squareup.okhttp.internal.tls.OkHostnameVerifier');
                Squareup_OkHostnameVerifier_Activity_1.verify.overload('java.lang.String', 'java.security.cert.X509Certificate').implementation = function(a, b) {
                    console.log('[+] Bypassing Squareup OkHostnameVerifier {1}: ' + a);
                    return true;
                };
            } catch (err) {
                console.log('[-] Squareup OkHostnameVerifier check not found');
                //console.log(err);
                errDict[err] = ['com.squareup.okhttp.internal.tls.OkHostnameVerifier', 'verify'];
            }
            try {
                // Bypass Squareup OkHostnameVerifier {2}
                var Squareup_OkHostnameVerifier_Activity_2 = Java.use('com.squareup.okhttp.internal.tls.OkHostnameVerifier');
                Squareup_OkHostnameVerifier_Activity_2.verify.overload('java.lang.String', 'javax.net.ssl.SSLSession').implementation = function(a, b) {
                    console.log('[+] Bypassing Squareup OkHostnameVerifier {2}: ' + a);
                    return true;
                };
            } catch (err) {
                console.log('[-] Squareup OkHostnameVerifier check not found');
                //console.log(err);
                errDict[err] = ['com.squareup.okhttp.internal.tls.OkHostnameVerifier', 'verify'];
            }
    
    
            
    
            // Android WebViewClient (quadruple bypass) //
            //////////////////////////////////////////////
            try {
                // Bypass WebViewClient {1} (deprecated from Android 6)
                var AndroidWebViewClient_Activity_1 = Java.use('android.webkit.WebViewClient');
                AndroidWebViewClient_Activity_1.onReceivedSslError.overload('android.webkit.WebView', 'android.webkit.SslErrorHandler', 'android.net.http.SslError').implementation = function(obj1, obj2, obj3) {
                    console.log('[+] Bypassing Android WebViewClient check {1}');
                };
            } catch (err) {
                console.log('[-] Android WebViewClient {1} check not found');
                //console.log(err)
                errDict[err] = ['android.webkit.WebViewClient', 'onReceivedSslError'];
            }
            // Not working properly temporarily disused
            //try {
            //	// Bypass WebViewClient {2}
            //	var AndroidWebViewClient_Activity_2 = Java.use('android.webkit.WebViewClient');
            //	AndroidWebViewClient_Activity_2.onReceivedHttpError.overload('android.webkit.WebView', 'android.webkit.WebResourceRequest', 'android.webkit.WebResourceResponse').implementation = function(obj1, obj2, obj3) {
            //		console.log('[+] Bypassing Android WebViewClient check {2}');
            //	};
            //} catch (err) {
            //	console.log('[-] Android WebViewClient {2} check not found');
            //	//console.log(err)
            //	errDict[err] = ['android.webkit.WebViewClient', 'onReceivedHttpError'];
            //}
            try {
                // Bypass WebViewClient {3}
                var AndroidWebViewClient_Activity_3 = Java.use('android.webkit.WebViewClient');
                //AndroidWebViewClient_Activity_3.onReceivedError.overload('android.webkit.WebView', 'int', 'java.lang.String', 'java.lang.String').implementation = function(obj1, obj2, obj3, obj4) {
                AndroidWebViewClient_Activity_3.onReceivedError.implementation = function(view, errCode, description, failingUrl) {
                    console.log('[+] Bypassing Android WebViewClient check {3}');
                };
            } catch (err) {
                console.log('[-] Android WebViewClient {3} check not found');
                //console.log(err)
                errDict[err] = ['android.webkit.WebViewClient', 'onReceivedError'];
            }
            try {
                // Bypass WebViewClient {4}
                var AndroidWebViewClient_Activity_4 = Java.use('android.webkit.WebViewClient');
                AndroidWebViewClient_Activity_4.onReceivedError.overload('android.webkit.WebView', 'android.webkit.WebResourceRequest', 'android.webkit.WebResourceError').implementation = function(obj1, obj2, obj3) {
                    console.log('[+] Bypassing Android WebViewClient check {4}');
                };
            } catch (err) {
                console.log('[-] Android WebViewClient {4} check not found');
                //console.log(err)
                errDict[err] = ['android.webkit.WebViewClient', 'onReceivedError'];
            }
            
    
    
    
            // Apache Cordova WebViewClient //
            //////////////////////////////////
            try {
                var CordovaWebViewClient_Activity = Java.use('org.apache.cordova.CordovaWebViewClient');
                CordovaWebViewClient_Activity.onReceivedSslError.overload('android.webkit.WebView', 'android.webkit.SslErrorHandler', 'android.net.http.SslError').implementation = function(obj1, obj2, obj3) {
                    console.log('[+] Bypassing Apache Cordova WebViewClient check');
                    obj3.proceed();
                };
            } catch (err) {
                console.log('[-] Apache Cordova WebViewClient check not found');
                //console.log(err);
            }
    
    
    
    
            // Boye AbstractVerifier //
            ///////////////////////////
            try {
                var boye_AbstractVerifier = Java.use('ch.boye.httpclientandroidlib.conn.ssl.AbstractVerifier');
                boye_AbstractVerifier.verify.implementation = function(host, ssl) {
                    console.log('[+] Bypassing Boye AbstractVerifier check for: ' + host);
                };
            } catch (err) {
                console.log('[-] Boye AbstractVerifier check not found');
                //console.log(err);
                errDict[err] = ['ch.boye.httpclientandroidlib.conn.ssl.AbstractVerifier', 'verify'];
            }
    
    
    
            // Apache AbstractVerifier (quadruple bypass) //
            ////////////////////////////////////////////////
            try {
                var apache_AbstractVerifier_1 = Java.use('org.apache.http.conn.ssl.AbstractVerifier');
                apache_AbstractVerifier_1.verify.overload('java.lang.String', 'java.security.cert.X509Certificate').implementation = function(a, b) {
                    console.log('[+] Bypassing Apache AbstractVerifier {1} check for: ' + a);
                    return;
                };
            } catch (err) {
                console.log('[-] Apache AbstractVerifier {1} check not found');
                //console.log(err);
                errDict[err] = ['org.apache.http.conn.ssl.AbstractVerifier', 'verify'];
            }
                    try {
                var apache_AbstractVerifier_2 = Java.use('org.apache.http.conn.ssl.AbstractVerifier');
                apache_AbstractVerifier_2.verify.overload('java.lang.String', 'javax.net.ssl.SSLSocket').implementation = function(a, b) {
                    console.log('[+] Bypassing Apache AbstractVerifier {2} check for: ' + a);
                    return;
                };
            } catch (err) {
                console.log('[-] Apache AbstractVerifier {2} check not found');
                //console.log(err);
                errDict[err] = ['org.apache.http.conn.ssl.AbstractVerifier', 'verify'];
            }
                    try {
                var apache_AbstractVerifier_3 = Java.use('org.apache.http.conn.ssl.AbstractVerifier');
                apache_AbstractVerifier_3.verify.overload('java.lang.String', 'javax.net.ssl.SSLSession').implementation = function(a, b) {
                    console.log('[+] Bypassing Apache AbstractVerifier {3} check for: ' + a);
                    return;
                };
            } catch (err) {
                console.log('[-] Apache AbstractVerifier {3} check not found');
                //console.log(err);
                errDict[err] = ['org.apache.http.conn.ssl.AbstractVerifier', 'verify'];
            }
                    try {
                var apache_AbstractVerifier_4 = Java.use('org.apache.http.conn.ssl.AbstractVerifier');
                apache_AbstractVerifier_4.verify.overload('java.lang.String', '[Ljava.lang.String;', '[Ljava.lang.String;', 'boolean').implementation = function(a, b, c, d) {
                    console.log('[+] Bypassing Apache AbstractVerifier {4} check for: ' + a);
                    return;
                };
            } catch (err) {
                console.log('[-] Apache AbstractVerifier {4} check not found');
                //console.log(err);
                errDict[err] = ['org.apache.http.conn.ssl.AbstractVerifier', 'verify'];
            }
    
    
    
    
            // Chromium Cronet //
            /////////////////////
            try {
                var CronetEngineBuilderImpl_Activity = Java.use("org.chromium.net.impl.CronetEngineBuilderImpl");
                // Setting argument to TRUE (default is TRUE) to disable Public Key pinning for local trust anchors
                CronetEngine_Activity.enablePublicKeyPinningBypassForLocalTrustAnchors.overload('boolean').implementation = function(a) {
                    console.log("[+] Disabling Public Key pinning for local trust anchors in Chromium Cronet");
                    var cronet_obj_1 = CronetEngine_Activity.enablePublicKeyPinningBypassForLocalTrustAnchors.call(this, true);
                    return cronet_obj_1;
                };
                // Bypassing Chromium Cronet pinner
                CronetEngine_Activity.addPublicKeyPins.overload('java.lang.String', 'java.util.Set', 'boolean', 'java.util.Date').implementation = function(hostName, pinsSha256, includeSubdomains, expirationDate) {
                    console.log("[+] Bypassing Chromium Cronet pinner: " + hostName);
                    var cronet_obj_2 = CronetEngine_Activity.addPublicKeyPins.call(this, hostName, pinsSha256, includeSubdomains, expirationDate);
                    return cronet_obj_2;
                };
            } catch (err) {
                console.log('[-] Chromium Cronet pinner not found')
                //console.log(err);
            }
    
    
    
    
            // Flutter Pinning packages http_certificate_pinning and ssl_pinning_plugin (double bypass) //
            //////////////////////////////////////////////////////////////////////////////////////////////
            try {
                // Bypass HttpCertificatePinning.check {1}
                var HttpCertificatePinning_Activity = Java.use('diefferson.http_certificate_pinning.HttpCertificatePinning');
                HttpCertificatePinning_Activity.checkConnexion.overload("java.lang.String", "java.util.List", "java.util.Map", "int", "java.lang.String").implementation = function (a, b, c ,d, e) {
                    console.log('[+] Bypassing Flutter HttpCertificatePinning : ' + a);
                    return true;
                };
            } catch (err) {
                console.log('[-] Flutter HttpCertificatePinning pinner not found');
                //console.log(err);
                errDict[err] = ['diefferson.http_certificate_pinning.HttpCertificatePinning', 'checkConnexion'];
            }
            try {
                // Bypass SslPinningPlugin.check {2}
                var SslPinningPlugin_Activity = Java.use('com.macif.plugin.sslpinningplugin.SslPinningPlugin');
                SslPinningPlugin_Activity.checkConnexion.overload("java.lang.String", "java.util.List", "java.util.Map", "int", "java.lang.String").implementation = function (a, b, c ,d, e) {
                    console.log('[+] Bypassing Flutter SslPinningPlugin: ' + a);
                    return true;
                };
            } catch (err) {
                console.log('[-] Flutter SslPinningPlugin pinner not found');
                //console.log(err);
                errDict[err] = ['com.macif.plugin.sslpinningplugin.SslPinningPlugin', 'checkConnexion'];
            }
            
            
            
            
            // Unusual/obfuscated pinners bypass //
            ///////////////////////////////////////
            try {
                // Iterating all caught pinner errors and try to overload them 
                for (var key in errDict) {
                    var errStr = key;
                    var targetClass = errDict[key][0]
                    var targetFunc = errDict[key][1]
                    var retType = Java.use(targetClass)[targetFunc].returnType.type;
                    //console.log("errDict content: "+errStr+" "+targetClass+"."+targetFunc);
                    if (String(errStr).includes('.overload')) {
                        overloader(errStr, targetClass, targetFunc,retType);
                    }
                }
            } catch (err) {
                //console.log('[-] The pinner "'+targetClass+'.'+targetFunc+'" is not unusual/obfuscated, skipping it..');
                //console.log(err);
            }
    
    
    
            
            // Dynamic SSLPeerUnverifiedException Bypasser                               //
            // An useful technique to bypass SSLPeerUnverifiedException failures raising //
            // when the Android app uses some uncommon SSL Pinning methods or an heavily //
            // code obfuscation. Inspired by an idea of: https://github.com/httptoolkit  //
            ///////////////////////////////////////////////////////////////////////////////
            try {
                var UnverifiedCertError = Java.use('javax.net.ssl.SSLPeerUnverifiedException');
                UnverifiedCertError.$init.implementation = function (reason) {
                    try {
                        var stackTrace = Java.use('java.lang.Thread').currentThread().getStackTrace();
                        var exceptionStackIndex = stackTrace.findIndex(stack =>
                            stack.getClassName() === "javax.net.ssl.SSLPeerUnverifiedException"
                        );
                        // Retrieve the method raising the SSLPeerUnverifiedException
                        var callingFunctionStack = stackTrace[exceptionStackIndex + 1];
                        var className = callingFunctionStack.getClassName();
                        var methodName = callingFunctionStack.getMethodName();
                        var callingClass = Java.use(className);
                        var callingMethod = callingClass[methodName];
                        console.log('\x1b[36m[!] Unexpected SSLPeerUnverifiedException occurred related to the method "'+className+'.'+methodName+'"\x1b[0m');
                        //console.log("Stacktrace details:\n"+stackTrace);
                        // Checking if the SSLPeerUnverifiedException was generated by an usually negligible (not blocking) method
                        if (className == 'com.android.org.conscrypt.ActiveSession' || className == 'com.google.android.gms.org.conscrypt.ActiveSession') {
                            throw 'Reason: skipped SSLPeerUnverifiedException bypass since the exception was raised from a (usually) non blocking method on the Android app';
                        }
                        else {
                            console.log('\x1b[34m[!] Starting to dynamically circumvent the SSLPeerUnverifiedException for the method "'+className+'.'+methodName+'"...\x1b[0m');
                            var retTypeName = callingMethod.returnType.type;			
                            // Skip it when the calling method was already bypassed with Frida
                            if (!(callingMethod.implementation)) {
                                // Trying to bypass (via implementation) the SSLPeerUnverifiedException if due to an uncommon SSL Pinning method
                                callingMethod.implementation = function() {
                                    console.log('\x1b[34m[+] Bypassing the unusual/obfuscated pinner "'+className+'.'+methodName+'" via Frida function implementation\x1b[0m');
                                    returner(retTypeName);
                                }
                            }
                        }
                    } catch (err2) {
                        // Dynamic circumvention via function implementation does not works, then trying via function overloading
                        if (String(err2).includes('.overload')) {
                            overloader(err2, className, methodName, retTypeName);
                        } else {
                            if (String(err2).includes('SSLPeerUnverifiedException')) {
                                console.log('\x1b[36m[-] Failed to dynamically circumvent SSLPeerUnverifiedException -> '+err2+'\x1b[0m');
                            } else {
                                //console.log('\x1b[36m[-] Another kind of exception raised during overloading  -> '+err2+'\x1b[0m');
                            }
                        }
                    }
                    //console.log('\x1b[36m[+] SSLPeerUnverifiedException hooked\x1b[0m');
                    return this.$init(reason);
                };
            } catch (err1) {
                //console.log('\x1b[36m[-] SSLPeerUnverifiedException not found\x1b[0m');
                //console.log('\x1b[36m'+err1+'\x1b[0m');
            }
            
     
        });
        
    }, 0);
    
    
    
    
    function returner(typeName) {
        // This is a improvable rudimentary fix, if not works you can patch it manually
        //console.log("typeName: "+typeName)
        if (typeName === undefined || typeName === 'void') {
            return;
        } else if (typeName === 'boolean') {
            return true;
        } else {
            return null;
        }
    }
    
    
    function overloader(errStr, targetClass, targetFunc, retType) {
        // One ring to overload them all.. ;-)
        var tClass = Java.use(targetClass);
        var tFunc = tClass[targetFunc];
        var params = [];
        var argList = [];
        var overloads = tFunc.overloads;
        var returnTypeName = retType;
        var splittedList = String(errStr).split('.overload');
        for (var n=1; n<splittedList.length; n++) {
            var extractedOverload = splittedList[n].trim().split('(')[1].slice(0,-1).replaceAll("'","");
            // Discarding useless error strings
            if (extractedOverload.includes('<signature>')) {
                continue;
            }
            console.log('\x1b[34m[!] Found the unusual/obfuscated pinner "'+targetClass+'.'+targetFunc+'('+extractedOverload+')"\x1b[0m');
            // Check if extractedOverload is empty
            if (!extractedOverload) {
                // Overloading method withouth arguments
                tFunc.overload().implementation = function() {
                    var printStr = printer();
                    console.log('\x1b[34m[+] Bypassing the unusual/obfuscated pinner "'+targetClass+'.'+targetFunc+'('+extractedOverload+')"'+printStr+'\x1b[0m');
                    returner(returnTypeName);
                }
            } else {
                // Check if extractedOverload has multiple arguments
                if (extractedOverload.includes(',')) {
                    argList = extractedOverload.split(', ');
                } 
                // Considering max 8 arguments for the method to overload (Note: increase it, if needed)
                if (argList.length == 0) {
                    tFunc.overload(extractedOverload).implementation = function(a) {
                        var printStr = printer();
                        console.log('\x1b[34m[+] Bypassing the unusual/obfuscated pinner "'+targetClass+'.'+targetFunc+'('+extractedOverload+')"'+printStr+'\x1b[0m');
                        returner(returnTypeName);
                    }
                } else if (argList.length == 2) {
                    tFunc.overload(argList[0], argList[1]).implementation = function(a,b) {
                        var printStr = printer(a);
                        console.log('\x1b[34m[+] Bypassing the unusual/obfuscated pinner "'+targetClass+'.'+targetFunc+'('+extractedOverload+')"'+printStr+'\x1b[0m');
                        returner(returnTypeName);
                    }
                } else if (argList.length == 3) {
                    tFunc.overload(argList[0], argList[1], argList[2]).implementation = function(a,b,c) {
                        var printStr = printer(a,b);
                        console.log('\x1b[34m[+] Bypassing the unusual/obfuscated pinner "'+targetClass+'.'+targetFunc+'('+extractedOverload+')"'+printStr+'\x1b[0m');
                        returner(returnTypeName);
                    }
                } else if (argList.length == 4) {
                    tFunc.overload(argList[0], argList[1], argList[2], argList[3]).implementation = function(a,b,c,d) {
                        var printStr = printer(a,b,c);
                        console.log('\x1b[34m[+] Bypassing the unusual/obfuscated pinner "'+targetClass+'.'+targetFunc+'('+extractedOverload+')"'+printStr+'\x1b[0m');
                        returner(returnTypeName);
                    }
                }  else if (argList.length == 5) {
                    tFunc.overload(argList[0], argList[1], argList[2], argList[3], argList[4]).implementation = function(a,b,c,d,e) {
                        var printStr = printer(a,b,c,d);
                        console.log('\x1b[34m[+] Bypassing the unusual/obfuscated pinner "'+targetClass+'.'+targetFunc+'('+extractedOverload+')"'+printStr+'\x1b[0m');
                        returner(returnTypeName);
                    }
                }  else if (argList.length == 6) {
                    tFunc.overload(argList[0], argList[1], argList[2], argList[3], argList[4], argList[5]).implementation = function(a,b,c,d,e,f) {
                        var printStr = printer(a,b,c,d,e);
                        console.log('\x1b[34m[+] Bypassing the unusual/obfuscated pinner "'+targetClass+'.'+targetFunc+'('+extractedOverload+')"'+printStr+'\x1b[0m');
                        returner(returnTypeName);
                    }
                }  else if (argList.length == 7) {
                    tFunc.overload(argList[0], argList[1], argList[2], argList[3], argList[4], argList[5], argList[6]).implementation = function(a,b,c,d,e,f,g) {
                        var printStr = printer(a,b,c,d,e,f);
                        console.log('\x1b[34m[+] Bypassing the unusual/obfuscated pinner "'+targetClass+'.'+targetFunc+'('+extractedOverload+')"'+printStr+'\x1b[0m');
                        returner(returnTypeName);
                    }
                }  else if (argList.length == 8) {
                    tFunc.overload(argList[0], argList[1], argList[2], argList[3], argList[4], argList[5], argList[6], argList[7]).implementation = function(a,b,c,d,e,f,g,h) {
                        var printStr = printer(a,b,c,d,e,f,g);
                        console.log('\x1b[34m[+] Bypassing the unusual/obfuscated pinner "'+targetClass+'.'+targetFunc+'('+extractedOverload+')"'+printStr+'\x1b[0m');
                        returner(returnTypeName);
                    }
                }
            }
            
        }
    }
    
    
    function printer(a,b,c,d,e,f,g,h) {
        // Build the string to print for the overloaded pinner
        var printList = [];
        var printStr = '';
        if (typeof a === 'string') {
            printList.push(a);
        }
        if (typeof b === 'string') {
            printList.push(b);
        }
        if (typeof c === 'string') {
            printList.push(c);
        }
        if (typeof d === 'string') {
            printList.push(d);
        }
        if (typeof e === 'string') {
            printList.push(e);
        }
        if (typeof f === 'string') {
            printList.push(f);
        }
        if (typeof g === 'string') {
            printList.push(g);
        }
        if (typeof h === 'string') {
            printList.push(h);
        }
        if (printList.length !== 0) {
            printStr = ' check for:';
            for (var i=0; i<printList.length; i++) {
                printStr += ' '+printList[i];
            }
        }
        return printStr;
    }
    

    /*

    TO IMPLEMENT:

    Exec Family

    int execl(const char *path, const char *arg0, ..., const char *argn, (char *)0);
    int execle(const char *path, const char *arg0, ..., const char *argn, (char *)0, char *const envp[]);
    int execlp(const char *file, const char *arg0, ..., const char *argn, (char *)0);
    int execlpe(const char *file, const char *arg0, ..., const char *argn, (char *)0, char *const envp[]);
    int execv(const char *path, char *const argv[]);
    int execve(const char *path, char *const argv[], char *const envp[]);
    int execvp(const char *file, char *const argv[]);
    int execvpe(const char *file, char *const argv[], char *const envp[]);

    */


    BufferedReader.readLine.overload('boolean').implementation = function() {
        var text = this.readLine.overload('boolean').call(this);
        if (text === null) {
            // just pass , i know it's ugly as hell but test != null won't work :(
        } else {
            var shouldFakeRead = (text.indexOf("ro.build.tags=test-keys") > -1);
            if (shouldFakeRead) {
                send("Bypass build.prop file read");
                text = text.replace("ro.build.tags=test-keys", "ro.build.tags=release-keys");
            }
        }
        return text;
    };

    var executeCommand = ProcessBuilder.command.overload('java.util.List');

    ProcessBuilder.start.implementation = function() {
        var cmd = this.command.call(this);
        var shouldModifyCommand = false;
        for (var i = 0; i < cmd.size(); i = i + 1) {
            var tmp_cmd = cmd.get(i).toString();
            if (tmp_cmd.indexOf("getprop") != -1 || tmp_cmd.indexOf("mount") != -1 || tmp_cmd.indexOf("build.prop") != -1 || tmp_cmd.indexOf("id") != -1) {
                shouldModifyCommand = true;
            }
        }
        if (shouldModifyCommand) {
            send("Bypass ProcessBuilder " + cmd);
            this.command.call(this, ["grep"]);
            return this.start.call(this);
        }
        if (cmd.indexOf("su") != -1) {
            send("Bypass ProcessBuilder " + cmd);
            this.command.call(this, ["justafakecommandthatcannotexistsusingthisshouldthowanexceptionwheneversuiscalled"]);
            return this.start.call(this);
        }

        return this.start.call(this);
    };

    if (useProcessManager) {
        var ProcManExec = ProcessManager.exec.overload('[Ljava.lang.String;', '[Ljava.lang.String;', 'java.io.File', 'boolean');
        var ProcManExecVariant = ProcessManager.exec.overload('[Ljava.lang.String;', '[Ljava.lang.String;', 'java.lang.String', 'java.io.FileDescriptor', 'java.io.FileDescriptor', 'java.io.FileDescriptor', 'boolean');

        ProcManExec.implementation = function(cmd, env, workdir, redirectstderr) {
            var fake_cmd = cmd;
            for (var i = 0; i < cmd.length; i = i + 1) {
                var tmp_cmd = cmd[i];
                if (tmp_cmd.indexOf("getprop") != -1 || tmp_cmd == "mount" || tmp_cmd.indexOf("build.prop") != -1 || tmp_cmd == "id") {
                    var fake_cmd = ["grep"];
                    send("Bypass " + cmdarr + " command");
                }

                if (tmp_cmd == "su") {
                    var fake_cmd = ["justafakecommandthatcannotexistsusingthisshouldthowanexceptionwheneversuiscalled"];
                    send("Bypass " + cmdarr + " command");
                }
            }
            return ProcManExec.call(this, fake_cmd, env, workdir, redirectstderr);
        };

        ProcManExecVariant.implementation = function(cmd, env, directory, stdin, stdout, stderr, redirect) {
            var fake_cmd = cmd;
            for (var i = 0; i < cmd.length; i = i + 1) {
                var tmp_cmd = cmd[i];
                if (tmp_cmd.indexOf("getprop") != -1 || tmp_cmd == "mount" || tmp_cmd.indexOf("build.prop") != -1 || tmp_cmd == "id") {
                    var fake_cmd = ["grep"];
                    send("Bypass " + cmdarr + " command");
                }

                if (tmp_cmd == "su") {
                    var fake_cmd = ["justafakecommandthatcannotexistsusingthisshouldthowanexceptionwheneversuiscalled"];
                    send("Bypass " + cmdarr + " command");
                }
            }
            return ProcManExecVariant.call(this, fake_cmd, env, directory, stdin, stdout, stderr, redirect);
        };
    }

    if (useKeyInfo) {
        KeyInfo.isInsideSecureHardware.implementation = function() {
            send("Bypass isInsideSecureHardware");
            return true;
        }
    }

    Java.perform(function() {
        console.log("");
        console.log("[.] Debug check bypass");

        var Debug = Java.use('android.os.Debug');
        Debug.isDebuggerConnected.implementation = function() {
            //console.log('isDebuggerConnected Bypassed !');
            return false;
        }


    });

    function waitForModule(moduleName) {
        return new Promise(function(resolve, reject) {
            const interval = setInterval(function() {
                const baseAddress = Module.findBaseAddress(moduleName);
                if (baseAddress !== null) {
                    clearInterval(interval);
                    resolve(baseAddress);
                }
            }, 1000); // Проверяем каждую секунду
        });
    }

    const libwhatsapp_base_adr = await waitForModule("libwhatsapp.so");
    console.log("libwhatsapp.so address => ", libwhatsapp_base_adr);

    let GpiaRegClient$calculateGpiaParameter$1 = Java.use("com.whatsapp.registration.integritysignals.GpiaRegClient$calculateGpiaParameter$1");
    GpiaRegClient$calculateGpiaParameter$1["$init"].implementation = function (anonymousClass671, str, c1kk, i) {
        console.log(`GpiaRegClient$calculateGpiaParameter$1.$init is called: anonymousClass671=${anonymousClass671}, str=${str}, c1kk=${c1kk}, i=${i}\n`);
        str = ""//CtcBARCnMGvAUZUM4dut0XAusUBMnfoZjxxjdpyVbiP2kh08nkW9RqXMVUc-05wrr5QnWj6XS85p7WyMej_Udl0J7iLB908kxL-B1a2Fde0wIXsuL4rDkXGVOONArKDopRyxrmbRwP_6drcBMdJlGNsO8An-cF1KPEgxcPaHDNvID5OvmYjSNpB735O1a9H5WrMe8AR_kgLWOKbPT4HmaNk4C1nqQAEk6zIGFaYR98mBl330LZj9H0-PR6jtVA7_FjugVEjNieZ_hos0rPuyMicfXlm5b_ihcZkaagFVr4P7ChyvypqH32OIBKIRygibsjz8xNQnZNfz_EFiJ4l9z8IE1hJ5O1X90oAknhiJjj-esPTCXQ92qe4ghmLQfGcmYMWdFE-n8MiFcGmgxlCtJGngsIZg1AghtWnlDb79U44N82fSPu0"
        
        this["$init"](anonymousClass671, str, c1kk, i);
    };

/*Interceptor.attach(libwhatsapp_base_adr.add(0xA4C138), {
    onEnter: function(args) {
        console.log("Param: " + args[1].readCString());
        console.log("hex: " + hexdump(args[2], {
            length: 4000, // Увеличиваем длину до 64 байт
            header: true,
            ansi: true
        }));
    },
    onLeave: function(retval) {
        var str = retval;
        console.log("[*] return=", str);
        return retval;
    }
});*/
/*
const Base64 = Java.use('java.util.Base64');
const ByteArrayOutputStream = Java.use('java.io.ByteArrayOutputStream');
const KeyStore = Java.use('java.security.KeyStore');

const keyStore = KeyStore.getInstance('AndroidKeyStore');
keyStore.load(null, null);
const aliases = keyStore.aliases();
var aliasUsed = ""
while (aliases.hasMoreElements()) {
    const alias = aliases.nextElement();
    aliasUsed = alias
    console.log('Alias: ' + alias);
}

console.log('Used alias: ' + aliasUsed);
const certificateChain = keyStore.getCertificateChain(aliasUsed);
const byteArrayOutputStream = ByteArrayOutputStream.$new();

if (certificateChain !== null) {
    for (let i = certificateChain.length - 1; i >= 0; i--) {
        const encodedCert = certificateChain[i].getEncoded();
        byteArrayOutputStream.write(encodedCert, 0, encodedCert.length);
    }
}

console.log('Authorization Header: ' + Base64.getEncoder().encodeToString(byteArrayOutputStream.toByteArray()));

const Base64 = Java.use('java.util.Base64');


let bn = Java.use("com.google.android.play.core.integrity.bn");
bn["a"].implementation = function (bnVar, str, j, j2, i) {
    console.log(`bn.a is called: bnVar=${bnVar}, str=${str}, j=${j}, j2=${j2}, i=${i}\n`);
    let result = this["a"](bnVar, str, j, j2, i);
    console.log(`bn.a result=${result}\n`);
    return result;
};
/*
let C18080wI = Java.use("X.0wI");
C18080wI["A03"].implementation = function (c18080wI, num, bArr) {
    console.log(`C18080wI.A03 is called: c18080wI=${c18080wI}, num=${num}, bArr=${bArr}`);
    let result = this["A03"](c18080wI, num, bArr);
    console.log('bArr: ' + Base64.getEncoder().encodeToString(bArr));

    console.log(`C18080wI.A03 result=${result}`);
    return result;
};

C18080wI["A07"].implementation = function (bArr, bArr2) {
    console.log(`C18080wI.A07 is called: bArr=${bArr}, bArr2=${bArr2}`);
    let result = this["A07"](bArr, bArr2);
    console.log('bArr: ' + Base64.getEncoder().encodeToString(bArr));
    console.log('bArr1: ' + Base64.getEncoder().encodeToString(bArr2));

    console.log(`C18080wI.A07 result=${result}`);
    return result;
};

let AnonymousClass707 = Java.use("X.707");
AnonymousClass707["BRB"].implementation = function (c6j7, str, map) {
    // Логируем информацию о вызове метода
    console.log(`AnonymousClass707.BRB is called: c6j7=${c6j7}, str=${str}, map=${map}`);

    let Exception = Java.use('java.lang.Exception');
    let stackTrace = Exception.$new().getStackTrace();
    for (let i = 0; i < stackTrace.length; i++) {
        console.log('Stack Trace:', stackTrace[i].toString());
    }

    /*let entrySet = map.entrySet();
    let iterator = entrySet.iterator();
    // Итерируем по записям и выводим ключи и значения
    while (iterator.hasNext()) {
        let entry = iterator.next();
        console.log('Entry:', entry);

        try {
            let key = entry.getKey();
            let value = entry.getValue();
            console.log(`Key: ${key}, Value: ${value}`);
        } catch (e) {
            console.log('Error accessing key or value: ' + e.message);
        }
    }

    console.log("code: " + map.get("registration_code"))

    //map.put("registration_code", "1")

    //console.log("after change: " + map.get("registration_code"))

    // Вызов оригинальной реализации метода
    return this["BRB"](c6j7, str, map);
};
*/

    Interceptor.attach(libwhatsapp_base_adr.add(0x9F0EBC), {
        onEnter: function(args) {
        },
        onLeave: function(retval) {
            var str = retval.readCString();
            if (str.indexOf('&') != -1 && str.indexOf('&gpia') != -1) {
                // Форматируем URL и параметры и отправляем их в Python-скрипт
                var url = str.split('&')[0];
                var params = str.substring(url.length);
                console.log(str)
            }

            if (str.indexOf('{') != -1)
                console.log(str)
    
            return retval;
        }
    });
    /*Interceptor.attach(libwhatsapp_base_adr.add(0x8322AC), {
        onEnter: function(args) {
            console.log("[*] hex in=: " + hexdump(args[0]));
        },
        onLeave: function(retval) {
            console.log("[*] hex=", hexdump(retval));
            return retval;
        }
    });
    Interceptor.attach(libwhatsapp_base_adr.add(0xA4C138), {
        onEnter: function(args) {
            console.log("Param: " + args[1].readCString());
            console.log("hex: " + hexdump(args[2], {
                length: 4000, // Увеличиваем длину до 64 байт
                header: true,
                ansi: true
            }));
        },
        onLeave: function(retval) {
            var str = retval;
            console.log("[*] return=", str);
            return retval;
        }
    });
   
    /*

    let bk = Java.use("com.google.android.play.core.integrity.bk");
    bk["c"].implementation = function (bundle) {
        console.log(`bk.c is called: bundle=${bundle}`);
        bundle.getString.overload('java.lang.String').implementation = function(key) {
            console.log("[*] Bundle.getString() called with key:", key);
            
            // Вызываем оригинальный метод getString()
            var result = this.getString(key);
    
            // Выводим результат в консоль
            console.log("[*] Result:", result);
            // Возвращаем результат
            return result;
        };
        this["c"](bundle);
    };*/
/*//CpYCARCnMGttlaFU4GZi21wcpwneYApg1HdVgz7y_hF7uxNeaH1iFUzhxGyLrnBcRr1aTPx4Vl700H_xTU9ShJiWIEk6EHl_BRv5P2XMyOUvk9T7ou6s-GWjAtwq7g3c14gnK1P3N0irQela96m9Z5Rk96o3U8wCx3SBnpHO7RUpFvUuZs-yW57IucO4z930BDVXxhu8c4dLf28FlNPcuAeLV4FsuppIghsFtHoieVr2r5unt9Ugd09d4PNBvq_yip9X9ANFVGO3uSmpCDv6FPDQwlZxjXnz_aF6wD5KHFz_7QxL6j_6oiTOPK5xVBCxOp--WujMLwBNlfC3MVnHUg02o1RSgIPmnxKd47NeOqIfnkmB2Aw9DSUaaQHDK6Ut8y0nLwqGX5P7WQWKUC0By2IopeBvuzhiKyEhwfHXJE-UTTyZEpeSzId2NjEoGL1R9FzNedbwVALOjFi7z5U8-143zLrYTTINWHaYdv3xN_mxt2Mz1zRvpWUMubB3QIdBhTA2Tw
    // Получаем ссылку на класс GpiaRegClient$fetchTokenBlocking$1
    const fetchTokenBlockingClass = Java.use(className);
GpiaRegClient$calculateGpiaParameter$1.invokeSuspend is called: obj=X.0U7
GpiaRegClient$calculateGpiaParameter$1.invokeSuspend result=COROUTINE_SUSPENDED

GpiaRegClient$calculateGpiaParameter$1.invokeSuspend is called: obj=sS4VP8s9LGylGV8c9X4RgKnzF+8VWLKaFeltsZWqd/s1XKskYbtdG6QrCguU9FYEKIGuQDYgu9OfXJQLX3/wa9M2L8jo6zKq0Zj9RASW9dkyqsg6upGCTi7P46zrPSInHlAzzHsFu4ys6SB+QPeWBrRKT6eVS4Np160WWuWUghdgONeeLdTAFOOjyVhGweQmANl7lxq6DfpgQp5F1yNljqPBnGQFftVnKU/k50qEqB3uisthbePn23M05+TFQrCKxI/UtnIx+3ed9E2Qm6l9TgLzXbAbyc886AEdijNlbbhSHfVB6WFmysngpVPBetcyMInDJWjhiwj1DzFgTSw5OMJC5AuASTHCXNbOyG8L9Y+nHVC26kBkFMODi2PhGnCUblbVN0ovo1J1e/lhCTFKdmexlcA3mFDG4x84sr0eoz3o98OT5NOBc1J/4mRPjFWjK2cvKjtIsx6K6/cFZGPD/eCo5hud+36nm0uD3ExBjUev3TSNpRlJESN9LQS33Qdy6YWf43S04X0QignSAceYyAWv5y7REcWkSOvWTs+VIfjtjrZDU9J21Yg9XxePpD5MfZdQWBlJawZcz5lQpypU9eCSAiRGvXTiSb1My/o/OQTRObxwcxJLRJ+D9dFJSFGWChnfpk1LDknMeqXnuKslduDdwm0GmsmZP8pVS9CilWV37YtWrKZl17AoWh+Tq9tr+MB7UjcqAEXhGggVRf8Ccnk159jCUDzKB6Xb2TZ9BNVhn19DAkGTTx3pEig87VpcLhO4qCrbiAefiskjTE8VPiTrRPApMxt9yLOfba+7GecEkKacyEBLV8uUBXka8OFRZrgQ47oFua3vjk2r82t9op/claUM56e+t/PnftOuKwedqHwx673OLDeBqFI256NQRU9ftdOG1DL3c13+vAo/jgdAf76swiAesOUssyuRhoCr3QmNjkZX9p9cDBBCWgcBzpcgx8cGEApOiH/0Uan0UmzsuGnXkvEdYIv5Pc4R2mjhrX67GeAuR66KyqI8lS5r9Ir6Cp4crL0e4GU9iHIjdLfShIsUG34kYbq5+0EIreWleZd7vlIUGXx6OkObO1o8Dk8D/fBjiDaPRbp2p+vn4Q==
GpiaRegClient$calculateGpiaParameter$1.invokeSuspend result=sS4VP8s9LGylGV8c9X4RgKnzF+8VWLKaFeltsZWqd/s1XKskYbtdG6QrCguU9FYEKIGuQDYgu9OfXJQLX3/wa9M2L8jo6zKq0Zj9RASW9dkyqsg6upGCTi7P46zrPSInHlAzzHsFu4ys6SB+QPeWBrRKT6eVS4Np160WWuWUghdgONeeLdTAFOOjyVhGweQmANl7lxq6DfpgQp5F1yNljqPBnGQFftVnKU/k50qEqB3uisthbePn23M05+TFQrCKxI/UtnIx+3ed9E2Qm6l9TgLzXbAbyc886AEdijNlbbhSHfVB6WFmysngpVPBetcyMInDJWjhiwj1DzFgTSw5OMJC5AuASTHCXNbOyG8L9Y+nHVC26kBkFMODi2PhGnCUblbVN0ovo1J1e/lhCTFKdmexlcA3mFDG4x84sr0eoz3o98OT5NOBc1J/4mRPjFWjK2cvKjtIsx6K6/cFZGPD/eCo5hud+36nm0uD3ExBjUev3TSNpRlJESN9LQS33Qdy6YWf43S04X0QignSAceYyAWv5y7REcWkSOvWTs+VIfjtjrZDU9J21Yg9XxePpD5MfZdQWBlJawZcz5lQpypU9eCSAiRGvXTiSb1My/o/OQTRObxwcxJLRJ+D9dFJSFGWChnfpk1LDknMeqXnuKslduDdwm0GmsmZP8pVS9CilWV37YtWrKZl17AoWh+Tq9tr+MB7UjcqAEXhGggVRf8Ccnk159jCUDzKB6Xb2TZ9BNVhn19DAkGT
    // Получаем все методы класса
    const methods = fetchTokenBlockingClass.class.getDeclaredMethods();

    // Перехватываем все методы
    methods.forEach(function(method) {
        // Получаем имя метода
        const methodName = method.getName();

        console.log(methodName)
        // Перехватываем метод и выводим его имя
        fetchTokenBlockingClass[methodName].implementation = function() {
            console.log("[*] Intercepting method", methodName, "in class", className);
            
                        // Преобразуем объект Arguments в массив
            const argsArray = Array.prototype.slice.call(arguments);
            console.log("[*] Arguments:", argsArray);

            const methods1 = argsArray[0].class.toString();
                console.log("[*] so name:", methods1);
            // Вызываем оригинальный метод с переданными аргументами и получаем результат
            const result = this[methodName].apply(this, arguments);
            console.log("[*] Result:", result);

            // Возвращаем результат
            return result;
        };
    });*/
});
