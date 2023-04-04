import os, json
import boto3
import base64
from flask import g
from flask import Flask, jsonify, request, render_template, redirect, url_for, flash, session
from botocore.exceptions import ClientError, NoCredentialsError
from datetime import datetime, timedelta
from dotenv import load_dotenv


from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from wtforms.validators import InputRequired, Length, ValidationError
from flask_bcrypt import Bcrypt

from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Email, Length, EqualTo, ValidationError, Optional, URL

import mimetypes


load_dotenv()
ALLOWED_EXTENSIONS = os.environ.get('ALLOWED_EXTENSIONS', '').split(',')


db = SQLAlchemy() # db intitialized here
app = Flask(__name__, static_url_path='/static')

# db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv("SQLALCHEMY_DATABASE_URI")
app.config['SECRET_KEY'] = os.getenv("SECRET_KEY")
app.config['PERMANENT_SESSION_LIFETIME'] = int(os.getenv("PERMANENT_SESSION_LIFETIME", 1800)) # 30 minutes in seconds

db.init_app(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# model
class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True, nullable=False)
    password = db.Column(db.String(128), nullable=False)
    aws_access_key_id = db.Column(db.String(255))
    aws_secret_access_key = db.Column(db.String(255))
    endpoint_url = db.Column(db.String(255))
    region = db.Column(db.String(255))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime, default=None)
    last_logout = db.Column(db.DateTime, default=None)
    ip_address = db.Column(db.String(45), nullable=True)

    @staticmethod
    def on_login(user):
        user.last_login = datetime.utcnow()
        user.ip_address = request.remote_addr
        db.session.commit()

    @staticmethod
    def on_logout(user):
        user.last_logout = datetime.utcnow()
        db.session.commit()

# RegistrationForm
class RegistrationForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email(), Length(min=4, max=255)])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=8, max=128)])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password', message='Passwords must match')])
    aws_access_key_id = StringField('S3 Access Key', validators=[DataRequired(), Length(max=255)])
    aws_secret_access_key = PasswordField('S3 Secret Access Key', validators=[DataRequired(), Length(max=255)])
    endpoint_url = StringField('Endpoint URL', validators=[Optional(), URL(), Length(max=255)])
    region = StringField('Region', validators=[Optional(), Length(max=255)])
    register_access_key_id = StringField('Register Access Key', validators=[DataRequired(), Length(max=255)])
    submit = SubmitField('Register')

    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user:
            flash('Email is already taken.', 'danger')
            raise ValidationError('Email is already taken.')

        
# LoginForm
class LoginForm(FlaskForm):
    email = StringField(validators=[DataRequired(), Email(), Length(min=4, max=255)], render_kw={"placeholder": "Email"})
    password = PasswordField(validators=[InputRequired(), Length(min=8, max=128)], render_kw={"placeholder": "Password"})
    submit = SubmitField('Login')

# User()
with app.app_context():
    db.create_all()



# @app.route('/')
# def index():
#     return render_template('index.html')

def init_s3_client():
    try:
        s3_client = boto3.client(
            's3',
            aws_access_key_id=current_user.aws_access_key_id,
            aws_secret_access_key=current_user.aws_secret_access_key,
            endpoint_url=current_user.endpoint_url,
            region_name=current_user.region if current_user.region else 'BKK'
        )
        return s3_client
    except Exception as e:
        flash("Error creating S3 resource. Please check your credentials and try again.")
        logout_user()
        return False

def before_request():
    if current_user.is_authenticated:
        init_s3_client()

# Register the before_request function
app.before_request(before_request)


@app.route('/', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        # Retrieve the user from the database based on their email address
        user = User.query.filter_by(email=form.email.data).first()
        # Check that the user exists and that their password is correct
        if user is not None and bcrypt.check_password_hash(user.password, form.password.data):
            # Log the user in and redirect them to the homepage
            login_user(user)
            # update the last_login field of the logged-in user with the current time.
            User.on_login(user)  # record the user's IP address on login
            # flash('You have been logged in successfully.', 'success')
            next_page = request.args.get('next')
            return redirect(next_page) if next_page else redirect(url_for('bucket'))
        else:
            # Display an error message if the login details are invalid
            flash('Invalid email or password.', 'danger')
    # update the last_logout field of the logged-out user with the current time.
    User.on_logout(current_user)  # record the user's logout time
    logout_user()
    return render_template('index.html', form=form, title='Login')

@app.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
    # update the last_logout field of the logged-out user with the current time.
    User.on_logout(current_user)  # record the user's logout time
    logout_user()
    flash('You have been logged out.', 'success')
    return redirect(url_for('login'))


@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():

        # check register_access_key_id
        if form.register_access_key_id.data != os.getenv("SECRET_KEY"):
            flash('Invalid registration key', 'danger')
            return render_template('register.html', title='Register', form=form)
        
        hashed_password = bcrypt.generate_password_hash(form.password.data)
        user = User(email=form.email.data,
                    password=hashed_password,
                    aws_access_key_id=form.aws_access_key_id.data,
                    aws_secret_access_key=form.aws_secret_access_key.data,
                    endpoint_url=form.endpoint_url.data,
                    region=form.region.data)
        db.session.add(user)
        db.session.commit()
        flash('Account created successfully!', 'success')
        return redirect(url_for('login'))
    # return render_template('register.html', title='Register', form=form)
    return redirect(url_for('login'))



@app.route('/bucket')
@login_required
def bucket():
    # Initialize the s3 resource before using it
    s3_client = init_s3_client()
    if not s3_client:
        return redirect(url_for('login'))
    
    alert = request.args.get('alert')
    message = request.args.get('message')

    # List all S3 buckets in your account
    response = s3_client.list_buckets()

    # Print the bucket names
    buckets = []
    for bucket in response['Buckets']:
        bucket['CreationDate'] = convert_datetime(bucket['CreationDate'])
        buckets.append(bucket)
    # return jsonify({'buckets': buckets}), 200
    return render_template('bucket.html', 
                           buckets=buckets, 
                           alert=alert, 
                           message=message, 
                           email=current_user.email,
                           title='Bockets'
                           )


def convert_datetime(LastModified):
    # Add the UTC+7 timezone offset to the datetime object
    LastModified = LastModified + timedelta(hours=7)

    # Format the datetime object as a string with the desired format
    new_str = LastModified.strftime('%B %d, %Y, %H:%M:%S')
    return new_str

def convert_size(bytes):
    """
    Convert a number of bytes to either MB or GB depending on the size
    """
    mb = bytes / (1024) # Conversion factor for MB
    gb = bytes / (1024 * 1024) # Conversion factor for GB
    if gb >= 1:
        return f"{gb:.1f} MB"
    elif mb >= 1:
        return f"{mb:.1f} KB"
    else:
        return f"{bytes} KB"


@app.route('/bucket/<string:bucket_name>')
@login_required
def get_bucket(bucket_name):
    # Initialize the s3 resource before using it
    s3_client = init_s3_client()
    if not s3_client:
        return redirect(url_for('login'))

    prefix = request.args.get('prefix')
    print('prefix >>>>>>>> ', prefix)
    
    if prefix:
        sub_dirs = []
        str_sub_dir = ''
        for i, sub_dir in enumerate([d for d in prefix.split('/') if d != '']):
           
            str_sub_dir += f"{sub_dir}/"
            object_sub_dirs = {'label': sub_dir, 'value': str_sub_dir}
            if i == len([d for d in prefix.split('/') if d != '']) - 1:
                object_sub_dirs['disabled'] = True
            else:
                object_sub_dirs['disabled'] = False
            sub_dirs.append(object_sub_dirs)

        try:
            response = s3_client.list_objects_v2(Bucket=bucket_name, Prefix=prefix, Delimiter='/')
        except:
            message = "I'm sorry, Please check your permissions and try again later."
            alert = 'warning'
            return redirect(url_for('bucket', alert=alert, message=message))

        prefixs =  []
        for obj in response.get('CommonPrefixes', []):
            
            prefixs.append({
                'Prefix':obj.get('Prefix'),
                'Type': 'Folder',
                })


        # Loop through the contents of the bucket and print the keys of each object
        objects = []
        for obj in response.get('Contents', []):
            endpoint_url = current_user.endpoint_url
            url2 = endpoint_url.split('//')[0] + '//' + bucket_name + '.' + endpoint_url.split('//')[1] + '/' + obj['Key']
            type = obj['Key'].split('.')[-1]
            obj['Type'] = type
            obj['LastModified'] = convert_datetime(obj['LastModified'])
            obj['Size'] = convert_size(obj['Size'])
            obj['StorageClass'] = obj['StorageClass'].capitalize()
            obj['Url'] = f"{current_user.endpoint_url}/{bucket_name}/{obj['Key']}"
            obj['Url2'] = url2
            objects.append({
                **obj
            })

        # return jsonify({'objects': objects, 'prefixs': prefixs}), 200
        return render_template('bucket_name.html', 
                                prefixs=prefixs,
                                objects=objects,
                                bucket=bucket_name,
                                prefix=prefix, 
                                sub_dirs=sub_dirs,
                                email=current_user.email,
                                title=bucket_name
                                )

    # Use the list_objects_v2 method to get a list of objects in the bucket
    try:
        response = s3_client.list_objects_v2(Bucket=bucket_name, Prefix='', Delimiter='/')
    except:
        message = "I'm sorry, Please check your permissions and try again later."
        alert = 'warning'
        return redirect(url_for('bucket', alert=alert, message=message))


    prefixs =  []
    for obj in response.get('CommonPrefixes', []):
        prefixs.append({
            'Prefix':obj.get('Prefix'),
            'Type': 'Folder',
            })


    # Loop through the contents of the bucket and print the keys of each object
    objects = []
    for obj in response.get('Contents', []):
        endpoint_url = current_user.endpoint_url
        url2 = endpoint_url.split('//')[0] + '//' + bucket_name + '.' + endpoint_url.split('//')[1] + '/' + obj['Key']
        type = obj['Key'].split('.')[-1]
        obj['Type'] = type
        obj['LastModified'] = convert_datetime(obj['LastModified'])
        obj['Size'] = convert_size(obj['Size'])
        obj['StorageClass'] = obj['StorageClass'].capitalize()
        obj['Url'] = f"{current_user.endpoint_url}/{bucket_name}/{obj['Key']}"
        obj['Url2'] = url2
        objects.append({
            **obj
        })

    # return jsonify({'objects': objects, 'prefixs': prefixs}), 200
    return render_template('bucket_name.html',
                        prefixs=prefixs,
                        objects=objects,
                        bucket=bucket_name,
                        prefix='',
                        sub_dirs='',
                        email=current_user.email,
                        title=bucket_name
                                )

def is_valid_file(filename):
    ext = filename.split('.')[-1]
    if ext.lower() in ALLOWED_EXTENSIONS:
        return True
    else:
        return False


def upload_file(s3_client, file, bucket, object_key=None):
    """Upload a file to an S3 bucket

    :param file: File to upload
    :param bucket: Bucket to upload to
    :param object_key: S3 object name. If not specified then file is used
    :return: True if file was uploaded, else False
    """

    if is_valid_file(file.filename):
        content_type = mimetypes.guess_type(file.filename)[0]

        # If S3 object_key was not specified, use file
        if object_key is None:
            object_key = os.path.basename(file.filename)

        try:
            response = s3_client.upload_fileobj(file, bucket, object_key, ExtraArgs={'ContentType': content_type})

            if response is None:
                message = f'File uploaded {file.filename} successfully to S3 bucket!'
            else:
                message = f'File upload {file.filename} to S3 bucket failed.'

        except ClientError as e:
            message = f'Error upload file {file.filename}: {str(e)}'
            return False, message
        return True, message
    else:
        message = f'{file.filename} Invalid file type. Please upload images or PDFs only.'
        return False, message


@app.route('/bucket/<string:bucket_name>/create-folder', methods=['POST'])
@login_required
def create_folder(bucket_name):
    # Initialize the s3 resource before using it
    s3_client = init_s3_client()
    if not s3_client:
        return redirect(url_for('login'))
    prefix = request.args.get('prefix')
    if prefix:
        object_key = f"{prefix}"
    response = s3_client.put_object(Bucket=bucket_name, Body='', Key=(object_key))

    if response:
        message = 'Folder created successfully.'
        url1 = os.getenv("ENDPOINT") + '/' + bucket_name + '/' + object_key

        # https://pre-cosmenet.s3-bkk.nipa.cloud
        url2 = os.getenv("ENDPOINT").split('//')[0] + '//' + bucket_name + '.' + os.getenv("ENDPOINT").split('//')[1] + '/' + object_key
        
        return jsonify({'Url1': url1, 
                        'Url2': url2,
                        'Key': object_key, 
                        'message': message,
                        'success':True}), 201

    message = 'Failed to create folder in S3'
    return jsonify({'message': message, 'success': False}), 200
        

@app.route('/bucket/<string:bucket_name>/upload', methods=['POST'])
@login_required
def upload(bucket_name):
    try:
        # Initialize the s3 resource before using it
        s3_client = init_s3_client()
        if not s3_client:
            return redirect(url_for('login'))
        prefix = request.args.get('prefix')
        print('prefix upload >>>> ', prefix)

        files = request.files.getlist('files')

        results = []
        object_keys = []
        _status = []
        for file in files:
            # Do something with the file, such as saving it to disk or processing it
            filename = file.filename
            object_key = filename
            if prefix:
                object_key = f"{prefix}{filename}"

        
            result, message = upload_file(s3_client=s3_client, file=file, bucket=bucket_name, object_key=object_key)
            # if result:
            _status.append(result)
            object_keys.append(object_key)

            results.append({'message':message, 'success':result})
        message = 'File uploaded'
        return jsonify({'message': message,
                        'success':True,
                        'results': results,
                        'object_keys':object_keys,
                        'status':_status
                        }), 200
    except:
        return jsonify({'message': 'error', 'success':False}), 500
 

def delete_file(s3_client, bucket_name, key):
    try:
        s3_client.delete_object(Bucket=bucket_name, Key=key)
        message = f'File {key} deleted from bucket {bucket_name}'
        return True, message
    except NoCredentialsError:
        message = 'AWS credentials not available'
        return False, message
    except Exception as e:
        message = f'Error deleting file {key}: {str(e)}'
        return False, message
    

def delete_folder(s3_client, bucket_name, folder_path):
    try:
        # List all objects within the folder
        objects_to_delete = []
        paginator = s3_client.get_paginator('list_objects_v2')
        for result in paginator.paginate(Bucket=bucket_name, Prefix=folder_path):
            if 'Contents' in result:
                for obj in result['Contents']:
                    objects_to_delete.append({'Key': obj['Key']})

        # Delete all objects within the folder
        if len(objects_to_delete) > 0:
            s3_client.delete_objects(Bucket=bucket_name, Delete={'Objects': objects_to_delete})

        # Delete the folder object itself
        s3_client.delete_object(Bucket=bucket_name, Key=folder_path)
        print(f'Folder {folder_path} deleted from bucket {bucket_name}')
    except NoCredentialsError:
        print('AWS credentials not available')
    except Exception as e:
        print(f'Error deleting folder {folder_path}: {str(e)}')

@app.route('/bucket/<string:bucket_name>/delete/', methods=['DELETE'])
@login_required
def delete(bucket_name):
    # Initialize the s3 resource before using it
    s3_client = init_s3_client()
    if not s3_client:
        return redirect(url_for('login'))
    prefix = request.args.get('prefix')
    if prefix:
        res, message =  delete_file(s3_client=s3_client, bucket_name=bucket_name, key=prefix)
        print(message)
        if res:
            return jsonify({'message': message}), 200
        else:
            return jsonify({'message': message}), 200
    # Your logic for deleting the file with the given filename goes here
    
    return jsonify({'message': 'Not prefix'}), 200


@app.route('/object/<string:bucket_name>')
@login_required
def object(bucket_name):
    # Initialize the s3 resource before using it
    s3_client = init_s3_client()
    if not s3_client:
        return redirect(url_for('login'))
    prefix = request.args.get('prefix')
    if prefix:

        response_acl = s3_client.get_object_acl(Bucket=bucket_name, Key=prefix)
        response_meta = s3_client.head_object(Bucket=bucket_name, Key=prefix)

        # print('response_meta >>>>> ', response_meta)
        content_type = response_meta['ContentType']

        size = convert_size(response_meta['ContentLength'])
        lastModified = convert_datetime(response_meta['LastModified'])
        owner = response_acl['Owner']['DisplayName']
        url = f"{current_user.endpoint_url}/{bucket_name}/{prefix}"
        endpoint_url = current_user.endpoint_url
        url2 = endpoint_url.split('//')[0] + '//' + bucket_name + '.' + endpoint_url.split('//')[1] + '/' + prefix

        if prefix.split('/')[:-1]:
            back_prefix = f"?prefix={'/'.join(prefix.split('/')[:-1]) + '/'}"
        else:
            back_prefix = ''

        permission = ''
        for i, row in enumerate(response_acl.get('Grants', [])):

            if i == len(response_acl.get('Grants', [])) - 1:
                permission += row['Permission'] 
            else:
                permission += row['Permission'] + ', '


        return render_template('object.html',
                            prefix = prefix,
                            object_name=prefix.split('/')[-1],
                            bucket_name=bucket_name,
                            size=size,
                            lastModified=lastModified,
                            owner=owner,
                            permission=permission,
                            url=url,
                            url2=url2,
                            back_prefix=back_prefix,
                            email=current_user.email,
                            content_type=content_type,
                            title='Detail'
                            )    
    return jsonify({'message': bucket_name}), 200

@app.route('/bucket-policy/<string:bucket_name>')
@login_required
def get_bucket_policy(bucket_name):
    # Initialize the s3 resource before using it
    s3_client = init_s3_client()
    if not s3_client:
        return redirect(url_for('login'))
    # Get the bucket policy
    bucket_policy = s3_client.get_bucket_policy(Bucket=bucket_name)
    return jsonify({
        'bucket_policy': json.loads(bucket_policy['Policy'])
        }), 200

@app.route('/bucket-policy/<string:bucket_name>', methods=['PUT'])
@login_required
def update_bucket_policy(bucket_name):
    # Initialize the s3 resource before using it
    s3_client = init_s3_client()
    if not s3_client:
        return redirect(url_for('login'))
    policy_json = request.get_json()
 
    # Do something with the policy_json here
    # Put the bucket policy
    try:
        s3_client.put_bucket_policy(Bucket=bucket_name, Policy=json.dumps(json.loads(policy_json['permissions_json'])))
    except:
        return jsonify({'message': 'Failed to save policy.', 'bucket_name':bucket_name, 'success': False}), 403
    return jsonify({'message': 'Policy updated successfully', 'bucket_name':bucket_name, 'success': True})


@app.route('/upload/<string:bucket_name>', methods=['GET'])
@login_required
def upload_to(bucket_name):
    # Initialize the s3 resource before using it
    s3_client = init_s3_client()
    if not s3_client:
        return redirect(url_for('login'))

    prefix = request.args.get('prefix')
    shortened = request.args.get('values')
    values_str = base64.urlsafe_b64decode(shortened).decode('utf-8')
    values = json.loads(values_str)

    
    status = values.get('status')
    keys = values.get('keys')


    endpoint_url = current_user.endpoint_url
    if prefix:
        objects = []
        for i, key in enumerate(keys):
            obj = {}
            try:
                response_meta = s3_client.head_object(Bucket=bucket_name, Key=key)

                url1 = f"{endpoint_url}/{bucket_name}/{key}"
                url2 = endpoint_url.split('//')[0] + '//' + bucket_name + '.' + endpoint_url.split('//')[1] + '/' + key


                obj['Name'] = key.split('/')[-1]
                obj['Key'] = key
                obj['Folder'] = prefix.split('/')[-2] if len(prefix.split('/')) > 2 else  prefix.split('/')[0]
                obj['Url'] = url1
                obj['Url2'] = url2
                obj['ContentType'] = response_meta['ContentType']
                obj['ContentLength'] = convert_size(response_meta['ContentLength'])
                obj['LastModified'] = convert_datetime(response_meta['LastModified'])
                obj['Status'] = status[i]
            except:
                obj['Name'] = key.split('/')[-1]
                obj['Key'] = key
                obj['Folder'] = prefix.split('/')[-2] if len(prefix.split('/')) > 2 else  prefix.split('/')[0]
                obj['Url'] = ''
                obj['Url2'] = ''
                obj['ContentType'] = ''
                obj['ContentLength'] = ''
                obj['LastModified'] = ''
                obj['Status'] = status[i]
            
            objects.append(obj)


        return render_template('upload_to.html', objects=objects, title='Upload', bucket=bucket_name, prefix=prefix, email=current_user.email,)

        # return jsonify('upload_to.html',{
        #     'objects': objects,
        #     'bucket_name': bucket_name,
        #     'prefix': prefix,
        #     'title': 'Upload',
        # })
    
    objects = []
    for i, key in enumerate(keys):
        obj = {}
        try:
            response_meta = s3_client.head_object(Bucket=bucket_name, Key=key)
            url1 = f"{endpoint_url}/{bucket_name}/{key}"
            url2 = endpoint_url.split('//')[0] + '//' + bucket_name + '.' + endpoint_url.split('//')[1] + '/' + key

            obj['Name'] = key.split('/')[-1]
            obj['Key'] = key
            obj['Folder'] = ''
            obj['Url'] = url1
            obj['Url2'] = url2
            obj['ContentType'] = response_meta['ContentType']
            obj['ContentLength'] = convert_size(response_meta['ContentLength'])
            obj['LastModified'] = convert_datetime(response_meta['LastModified'])
            obj['Status'] = status[i]
        except:
            obj['Name'] = key.split('/')[-1]
            obj['Key'] = key
            obj['Folder'] = prefix.split('/')[-2] if len(prefix.split('/')) > 2 else  prefix.split('/')[0]
            obj['Url'] = ''
            obj['Url2'] = ''
            obj['ContentType'] = ''
            obj['ContentLength'] = ''
            obj['LastModified'] = ''
            obj['Status'] = status[i]
    
        objects.append(obj)


    return render_template('upload_to.html', objects=objects, title='Upload', bucket=bucket_name, prefix='', email=current_user.email)

@app.route('/search/<string:bucket_name>', methods=['POST'])
def search(bucket_name):
    # # Initialize the s3 resource before using it
    # s3_client = init_s3_client()
    # if not s3_client:
    #     return redirect(url_for('login'))
    s3_client = boto3.client(
            's3',
            aws_access_key_id=os.getenv("NIPA_KEY"),
            aws_secret_access_key=os.getenv("NIPA_SECRET_KEY"),
            endpoint_url=os.getenv("ENDPOINT"),
            region_name='BKK'
        )
    # endpoint_url = current_user.endpoinst_url 
    endpoint_url = os.getenv("ENDPOINT")
    query = request.get_json().get('query', '')
    prefix = request.args.get('prefix', '')
    if prefix:
        response = s3_client.list_objects_v2(Bucket=bucket_name, Prefix=f"{prefix}{query}", Delimiter='/')
        objects = []
        for obj in response.get('CommonPrefixes', []):
            
            objects.append({
                'Prefix':obj.get('Prefix'),
                'Type': 'Folder',
                'Folder': True,
                })


        # Loop through the contents of the bucket and print the keys of each object
        
        for obj in response.get('Contents', []):
            url2 = endpoint_url.split('//')[0] + '//' + bucket_name + '.' + endpoint_url.split('//')[1] + '/' + obj['Key']
            type = obj['Key'].split('.')[-1]
            obj['Type'] = type
            obj['LastModified'] = convert_datetime(obj['LastModified'])
            obj['Size'] = convert_size(obj['Size'])
            obj['StorageClass'] = obj['StorageClass'].capitalize()
            obj['Url'] = f"{endpoint_url}/{bucket_name}/{obj['Key']}"
            obj['Url2'] = url2
            obj['Folder'] = False
            objects.append({
                **obj
            })



    return jsonify({
        'objects':objects,
        'response':response
    })


@app.route('/s3')
def s3():
    return jsonify({'message': 's3 nipa connected'}), 200


if __name__=='__main__':
    app.run(host=os.getenv('IP', os.getenv("HOST")), port=int(os.getenv('PORT',os.getenv("POST"))), debug=bool(os.getenv("DEBUG")))