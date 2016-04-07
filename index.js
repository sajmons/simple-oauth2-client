exports.initialize = function(app, config) {
    require('./passportConf')(app, config);
    
    app.set('config', config);
    
    require('./routes')(app);
    var sslCert = require('./ssl_cert');    
    
    return {
        SSLCert: sslCert
    }
}