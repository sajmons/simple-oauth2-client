var crypto = require('crypto');
var tls = require('tls');
var fs = require('fs');
var path = require('path');
var empty = require('is-empty');

module.exports = function(dirname) {
    
    if (empty(dirname)) {
        throw new Error("Please set dirname to folder containing appropriate certificates"); 
    }
    
    require('ssl-root-cas/latest')
        .inject()
        .addFile(dirname + '/NovaVizijaCA_Root.crt');

    var folder = process.env.NODE_ENV || 'development';

    var exp = {};
    
    exp.privateKey = fs.readFileSync(path.join(dirname, folder + '/privatekey.pem')).toString();
    exp.certificate = fs.readFileSync(path.join(dirname, folder + '/certificate.pem')).toString();

    if (typeof tls.createSecureContext === 'function') {
        exp.credentials = tls.createSecureContext({
            key: exp.privateKey,
            cert: exp.certificate
        });
    } else {
        exp.credentials = crypto.createCredentials({
            key: exp.privateKey,
            cert: exp.certificate
        });
    }
    
    return exp;
}