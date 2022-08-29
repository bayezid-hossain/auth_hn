const dotenv = require('dotenv');
dotenv.config({ path: 'config/config.env' });
const S3 = require('aws-sdk/clients/s3');
const fs = require('fs');
const bucketName = process.env.AWS_BUCKET_NAME;
const region = process.env.AWS_BUCKET_REGION;
const accessKey = process.env.AWS_ACCESS_KEY_ID;
const secretAccessKey = process.env.AWS_SECRET_ACCESS_KEY;

const s3 = new S3({
  region,
  accessKey,
  secretAccessKey,
});
//uploads a file to s3
function uploadFile(file) {
  const fileStream = fs.createReadStream(file.filepath);
  const uploadParams = {
    Bucket: process.env.AWS_BUCKET_NAME,
    Body: fileStream,
    Key: file.newFilename,
  };

  return s3.upload(uploadParams).promise();
}

exports.uploadFile = uploadFile;

//download a file from s3

function getFilesStream(req, res, next) {
  const fileKey = req.params.key;
  const downloadParams = {
    Key: fileKey,
    Bucket: bucketName,
  };

  s3.getObject(downloadParams).createReadStream().pipe(res);
}
exports.getFilesStream = getFilesStream;
