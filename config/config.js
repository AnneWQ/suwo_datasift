module.exports = {
    db: 'mongodb://localhost/datasift',
    app: {
        name: 'Datasift Quota'
    },
    smtp: 'smtp.ecs.soton.ac.uk', //smtp server used for pass reset/newsletter
    recap_pbk: '6LfwcOoSAAAAACeZnHuWzlnOCbLW7AONYM2X9K-H', //recaptcha public key
    recap_prk: '6LfwcOoSAAAAAGFI7h_SJoCBwUkvpDRf7_r8ZA_D', //recaptcha private key
    quota_limit: 100
};
