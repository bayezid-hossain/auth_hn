const accountSID = 'AC954c87c16bf8b0aaa79ec3b867cc3457';
const accountAuth = 'f3f18e72649adb6936ac37a74c40539c';

// ** TWILIO **//

//as trial account the accountAuth changes frequently, don't get triggered
// if you don't recieve sms, i've sent the generated otp within the response
//and trial account may not send sms to other numbers than the number it was registered with

const twilio = require('twilio');

exports.sendOtp = (number, otp) => {
  const client = new twilio(accountSID, accountAuth);

  client.messages
    .create({
      body: `Your GO Verification cod is ${otp}`,
      to: `+88${number}`, // Text this number
      from: '+12055579134', // From a valid Twilio number
    })
    .then((message) => console.log(`Message ID: ${message.sid}`));
};

exports.generateOtp = () => {
  var digits = '0123456789';
  let OTP = '';
  for (let i = 0; i < 6; i++) {
    OTP += digits[Math.floor(Math.random() * 10)];
  }
  return OTP;
};
