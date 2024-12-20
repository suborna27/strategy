import os
from functools import wraps
from flask import Flask, render_template, redirect, url_for, flash, request, abort
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from forms import AdminLoginForm, TeamMemberForm, MemberLoginForm
from twilio.rest import Client
from dotenv import load_dotenv
load_dotenv()
app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///main.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'member_login'

# Admin credentials
TwilioSID = os.getenv("TWILIOACCOUNTSID")
TwilioAuth = os.getenv("TWILIOAUTHTOKEN")
Twilionumber = os.getenv("number")

twilio_client = Client(TwilioSID, TwilioAuth)


# Login manager user loader
@login_manager.user_loader
def load_user(user_id):
    return TeamMember.query.get(int(user_id))




def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Check if the user is authenticated and is an admin
        if not current_user.is_authenticated or current_user.username != ADMIN_USERNAME:
            abort(403)  # Forbidden access
        return f(*args, **kwargs)
    return decorated_function
# Models
class TeamMember(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    phonenumber = db.Column(db.String(100), nullable=False)
    role = db.Column(db.String(50), nullable=False, default='user')  # Default role

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def __repr__(self):
        return f"<TeamMember {self.username}>"

class Contact(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150), nullable=False)
    phonenumber = db.Column(db.String(100), unique=True, nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=True)

    def __repr__(self):
        return f"<Contact {self.name}>"


class MessageGroup(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150), nullable=False)
    conversation_sid = db.Column(db.String(150), unique=True, nullable=True)

    members = db.relationship('GroupMember', back_populates='group', cascade='all, delete-orphan')


class GroupMember(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    group_id = db.Column(db.Integer, db.ForeignKey('message_group.id'), nullable=False)
    member_type = db.Column(db.String(50), nullable=False)  # 'team_member' or 'contact'
    member_id = db.Column(db.Integer, nullable=False)

    group = db.relationship('MessageGroup', back_populates='members')

    def __repr__(self):
        return f"<GroupMember {self.member_type} {self.member_id}>"

# Routes






@app.route('/', methods=['GET', 'POST'])
def homepage():
    return redirect(url_for('member_login'))

@app.route('/admin/dashboard', methods=['GET'])
@login_required
def admin_dashboard():
    if current_user.username == 'admin':

        team_members = TeamMember.query.all()
        groups = MessageGroup.query.all()
        print(groups)
        phone_numbers = [Twilionumber, "+123456678"]  # Example phone numbers
        contacts = Contact.query.all()

        return render_template('admindash.html', team_members=team_members, groups= groups,phone_numbers=phone_numbers, contacts = contacts )
    else:
        return render_template('403.html')


@app.route('/add_contact', methods=['GET', 'POST'])
def add_contact():
    if request.method == 'POST':
        name = request.form['name']
        phonenumber = request.form['phonenumber']
        email = request.form['email']

        # Create a new contact
        new_contact = Contact(name=name, phonenumber=phonenumber, email=email)

        try:
            db.session.add(new_contact)
            db.session.commit()
            flash("Contact added successfully!", "success")
            return redirect(url_for('contacts'))
        except Exception as e:
            flash(f"Error adding contact: {e}", "danger")

    return redirect(url_for('admin_dashboard'))
@app.route('/edit/<int:id>', methods=['GET', 'POST'])
def edit_contact(id):
    contact = Contact.query.get_or_404(id)

    if request.method == 'POST':
        contact.name = request.form['name']
        contact.phonenumber = request.form['phonenumber']
        contact.email = request.form['email']

        try:
            db.session.commit()
            flash("Contact updated successfully!", "success")
            return redirect(url_for('index'))
        except Exception as e:
            flash(f"Error updating contact: {str(e)}", "danger")

    return render_template('edit_contact.html', contact=contact)


# Route to delete a contact
@app.route('/delete/<int:id>', methods=['POST'])
def delete_contact(id):
    contact = Contact.query.get_or_404(id)

    try:
        db.session.delete(contact)
        db.session.commit()
        flash("Contact deleted successfully!", "success")
    except Exception as e:
        flash(f"Error deleting contact: {str(e)}", "danger")

    return redirect(url_for('admin_dashboard'))












@app.route('/group/<int:id>', methods=['GET', 'POST'])
@login_required
def group(id):
    group = MessageGroup.query.get_or_404(id)
    group_members = []
    for member in group.members:
        if member.member_type == 'team_member':
            team_member = TeamMember.query.get(member.member_id)
            if team_member:
                group_members.append({
                    "username": team_member.username,
                    "phonenumber": team_member.phonenumber,
                    "member_type": "Team Member"
                })
        elif member.member_type == 'contact':
            contact = Contact.query.get(member.member_id)
            if contact:
                group_members.append({
                    "username": contact.name,
                    "phonenumber": contact.phonenumber,
                    "member_type": "Contact"
                })
    # Fetch team members and contacts
    team_members = TeamMember.query.all()
    contacts = Contact.query.all()

    # Fetch messages from Twilio
    conversation_sid = group.conversation_sid
    print(conversation_sid)
    if not conversation_sid:
        return "Invalid Conversation SID", 404

    participants = twilio_client.conversations.v1.conversations(conversation_sid).participants.list()
    for participant in participants:
        print(participant.messaging_binding)

    # Handle form submission for sending a new message
    if request.method == 'POST':
        message_body = request.form.get('message_body')
        print(message_body)

        if message_body:
            author_identity = current_user.phonenumber if hasattr(current_user, 'phonenumber') else "Guest"
            try:
                twilio_client.conversations.v1.conversations(conversation_sid).messages.create(
                    author= author_identity,
                    body=message_body
                )
                flash("Message sent successfully!", "success")
                print("message send successsfully")
            except Exception as e:
                flash(f"Error sending message: {str(e)}", "danger")
                print(f"Error sending message: {str(e)}")  # Print the error for debugging

    try:
        messages = twilio_client.conversations.v1.conversations(conversation_sid).messages.list()
        print(messages)
    except Exception as e:
        flash(f"Error fetching messages: {str(e)}", "danger")
        messages = []

    # Format messages for display
    conversation_messages = [
        {
            "sender": message.author,
            "body": message.body,
            "timestamp": message.date_created.strftime("%Y-%m-%d %H:%M:%S"),
        }
        for message in messages
    ]

    return render_template(
        'group.html',
        group=group,
        team_members=team_members,
        contacts=contacts,
        conversation_messages=conversation_messages,
        group_members=group_members
    )



@app.route('/group/<int:group_id>/add_member', methods=['POST'])
def add_member_to_group(group_id):
    group = MessageGroup.query.get_or_404(group_id)
    member_type = request.form['member_type']  # 'team_member' or 'contact'
    member_id = request.form['member_id']

    # Find the participant's phone number
    if member_type == 'team_member':
        participant = TeamMember.query.get(member_id)
        phonenumber = participant.phonenumber
        print(phonenumber)
        name  = participant.username
        twilio_client.conversations.v1.conversations(group.conversation_sid).participants.create(
            identity=name,  # Use identity for Twilio numbers
            messaging_binding_projected_address = phonenumber,

        )

    elif member_type == 'contact':
        participant = Contact.query.get(member_id)
        phonenumber = participant.phonenumber
        twilio_client.conversations.v1.conversations(group.conversation_sid).participants.create(
            messaging_binding_address =phonenumber
        )

    else:
        flash('Invalid member type')
        return redirect(url_for('group', id=group_id))  # Pass group ID for redirection

    # Add participant to Twilio Conversation

    # Add member to group in the database
    group_member = GroupMember(group_id=group.id, member_type=member_type, member_id=member_id)
    db.session.add(group_member)
    db.session.commit()

    flash(f'Member added successfully to the group: {group.name}')
    return redirect(url_for('group', id=group_id))  # Redirect back to the group page



@app.route('/admin/group/add', methods=['GET', 'POST'])
def addgroups():
    if request.method == 'POST':
        name = request.form['name']
        revised = name.replace(" ", "")  # Removes all spaces

        if not name:
            flash('Group name is required!')
            return redirect(url_for('manage_groups'))

        # Create a new Twilio conversation
        conversation = twilio_client.conversations.v1.conversations.create(
            friendly_name=revised
        )
        print(conversation.sid)

        # Save conversation SID in the database
        group = MessageGroup(name=revised, conversation_sid=conversation.sid)
        db.session.add(group)
        db.session.commit()
        flash('Group created successfully with Twilio Conversation!')
        return redirect(url_for('admin_dashboard'))

    groups = MessageGroup.query.all()
    return render_template('group.html', groups=groups)


@app.route('/admin/add', methods=['GET', 'POST'])
def add_team_member():


    phone_numbers = ["+18666995237", "+123456678"]  # Example phone numbers

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        phonenumber = request.form['phonenumber']
        role = request.form['role']
        # Validate form data
        if not username or not password or not phonenumber:
            flash('All fields are required!')
            return redirect(url_for('add_team_member'))

        # Check if username already exists
        existing_member = TeamMember.query.filter_by(username=username).first()
        if existing_member:
            flash('Username already exists!')
            return redirect(url_for('add_team_member'))

        # Create a new team member
        team_member = TeamMember(username=username, phonenumber=phonenumber, role=role)
        team_member.set_password(password)

        # Add and commit to the database
        db.session.add(team_member)
        db.session.commit()
        flash('Team member added successfully!')
        return redirect(url_for('admin_dashboard'))

    return render_template('add_team_member.html', phone_numbers=phone_numbers)



@app.route('/admin/edit/<int:id>', methods=['GET', 'POST'])
def edit_team_member(id):
    team_member = TeamMember.query.get_or_404(id)
    form = TeamMemberForm(obj=team_member)
    if form.validate_on_submit():
        team_member.username = form.username.data
        team_member.role = form.role.data
        team_member.set_password(form.password.data)  # Hash the updated password
        db.session.commit()
        flash('Team member updated successfully!')
        return redirect(url_for('admin_dashboard'))
    return render_template('edit_team_member.html', form=form)


@app.route('/admin/delete/<int:id>', methods=['POST'])
def delete_team_member(id):
    team_member = TeamMember.query.get_or_404(id)
    db.session.delete(team_member)
    db.session.commit()
    flash('Team member deleted successfully!')
    return redirect(url_for('admin_dashboard'))


@app.route('/login', methods=['GET', 'POST'])
def member_login():
    # Redirect to member dashboard if user is already logged in
    if current_user.is_authenticated:
        return redirect(url_for('member_dashboard'))

    form = MemberLoginForm()

    if form.validate_on_submit():
        # Check if the user exists in the database
        member = TeamMember.query.filter_by(username=form.username.data).first()
        if member and member.check_password(form.password.data):  # Validate password
            login_user(member)  # Log the user in
            # Redirect based on the user's role
            if member.role == 'admin':
                return redirect(url_for('admin_dashboard'))
            else:
                return redirect(url_for('member_dashboard'))
        else:
            flash('Invalid username or password', 'danger')  # Display error message

    # Render login form
    return render_template('member_login.html', form=form)



@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def member_dashboard():
    if current_user.role == 'admin':
        return redirect(url_for('admin_dashboard'))
    else:
        # Fetch groups where the current user is a member
        user_groups = db.session.query(MessageGroup).join(GroupMember).filter(
            GroupMember.member_type == 'team_member',
            GroupMember.member_id == current_user.id
        ).all()

        if request.method == 'POST':
            group_name = request.form['group_name']

            if not group_name:
                flash('Group name cannot be empty!')
                return redirect(url_for('member_dashboard'))

            # Create a new group and Twilio conversation
            conversation = twilio_client.conversations.v1.conversations.create(
                friendly_name=group_name
            )

            # Save the group in the database
            new_group = MessageGroup(name=group_name, conversation_sid=conversation.sid)
            db.session.add(new_group)
            db.session.commit()

            # Add the current user to the group as a member
            group_member = GroupMember(group_id=new_group.id, member_type='team_member', member_id=current_user.id)
            db.session.add(group_member)
            db.session.commit()

            flash(f'Group "{group_name}" created successfully!')
            return redirect(url_for('member_dashboard'))

    return render_template('member_dashboard.html', member=current_user, groups=user_groups)



@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('member_login'))


@app.route('/groups', methods = ['GET', 'POST'])
def groups():
    groups = MessageGroup.query.all()
    phone_numbers = [Twilionumber, "+123456678"]  # Example phone numbers

    return render_template('allgroups.html', groups=groups, phone_numbers=phone_numbers)


@app.route('/contacts', methods = ['GET', 'POST'])
def contacts():
    contacts = Contact.query.all()
    phone_numbers = [Twilionumber, "+123456678"]  # Example phone numbers

    return render_template('contacts.html', contacts=contacts,phone_numbers=phone_numbers)

@app.route('/team', methods = ['GET', 'POST'])
def team():
    team_members = TeamMember.query.all()

    phone_numbers = [Twilionumber, "+123456678"]  # Example phone numbers

    return render_template('team.html', team_members=team_members, phone_numbers=phone_numbers
                          )

    return render_template('team.html', contacts=contacts)
if __name__ == "__main__":
    with app.app_context():
        db.create_all()  # Initialize the database
    app.run(debug=True)
