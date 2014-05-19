/**
 * Module dependencies.
 */

var express = require('express'),
    fs = require('fs'),
    http = require('http'),
    path = require('path'),
    mongoose = require('mongoose'),
    passport = require("passport"),
    logger = require('./app/util/middleware/logger'),
    flash = require("connect-flash"),
    config = require('./config/config');

mongoose.connect(config.db);

var models_dir = __dirname + '/app/model';
fs.readdirSync(models_dir).forEach(function(file) {
    if (file[0] === '.') return;
    require(models_dir + '/' + file);
});

require('./config/passport')(passport, config);

var app = express();

app.locals.moment = require('moment');
app.configure(function() {
    app.set('port', process.env.PORT || 3000);
    app.set('views', __dirname + '/app/view');
    app.engine('jade', require('jade').__express);
    app.set('view engine', 'jade');
    //app.use(logger);
    app.use(express.favicon());
    app.use(express.logger('dev'));
    app.use(express.cookieParser());
    app.use(express.bodyParser());
    app.use(express.session({
        secret: 'keyboard cat'
    }));
    app.use(passport.initialize());
    app.use(passport.session());
    app.use(passport.authenticate('remember-me'));
    app.use(express.methodOverride());
    app.use(flash());
    app.use(app.router);
    app.use(express.static(path.join(__dirname, 'public')));
});

app.configure('development', function() {
    app.use(express.errorHandler());
});

app.use(function(err, req, res, next) {
    res.status(err.status || 500);
    res.render('500', {
        error: err
    });
});

app.use(function(req, res, next) {
    res.status(404);
    if (req.accepts('html')) {
        res.render('404', {
            url: req.url
        });
        return;
    }
    if (req.accepts('json')) {
        res.send({
            error: 'Not found'
        });
        return;
    }
    res.type('txt').send('Not found');
});

require('./config/router')(app, passport);

http.createServer(app).listen(app.get('port'), function() {
    console.log("Express server listening on port " + app.get('port'));
});

exports.app = app; //for vhost
