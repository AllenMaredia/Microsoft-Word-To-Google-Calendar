import docx2txt
from datetime import datetime, timezone, timedelta
from dateutil import tz
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
import os
import json
import tkinter as tk
from tkinter import filedialog
from flask_login import current_user
from database import db, User, UserToken, UserEvent


def extract_events_from_docx(docx_path):
    text = docx2txt.process(docx_path)
    lines = text.split('\n')

    events = []

    for line in lines:
        # Example: "1/29/24 : Exam 1"
        parts = line.split(' : ')
        if len(parts) == 2:
            date_str, event_name = parts
            try:
                date = datetime.strptime(date_str, "%m/%d/%y")
                events.append({'date': date.isoformat(),
                              'event_name': event_name})
            except ValueError:
                print(f"Error parsing date in line: {line}")

    return events


# Function to authenticate with Google Calendar API
def authenticate_google_calendar():
    SCOPES = ['https://www.googleapis.com/auth/calendar']

    user_token = UserToken.query.filter_by(user_id=current_user.id).first()

    if user_token:
        credentials = Credentials.from_authorized_user_info(
            {
                'token': None,
                'refresh_token': user_token.refresh_token,
                'token_uri': '',
                'client_id': '',
                'client_secret': '',
                'scopes': SCOPES,
            }
        )

        try:
            if not credentials.valid:
                if credentials.expired and credentials.refresh_token:
                    credentials.refresh(Request())
                    db.session.commit()  # Update the refreshed token in the database

            return credentials
        except Exception as e:
            # Handle the exception as needed
            print(f"Error during authentication: {e}")
            return None
    else:
        print("User token not found.")
        return None


# Function to add events to Google Calendar
def add_events_to_calendar(events):
    creds = authenticate_google_calendar()
    service = build('calendar', 'v3', credentials=creds)

    for event in events:
        event_date = event['date']
        event_name = event['event_name']

        event_date = datetime.fromisoformat(event['date'])
        
        event_date_user_tz_offset = -360

        # Adjust for the user's timezone if needed
        event_date_user_tz = event_date.replace(tzinfo=timezone(timedelta(minutes=event_date_user_tz_offset)))

        # Check if the event is already added for the specific user
        existing_event = UserEvent.query.filter_by(
        user_id=current_user.id, event_name=event_name, event_date=event_date_user_tz).first()

        if existing_event:
            print(
                f"Event '{event_name}' already added for user {current_user.id} on {event_date_user_tz}")
        else:
            # Add the event to the database
            new_event = UserEvent(
                event_name=event_name, event_date=event_date_user_tz, user_id=current_user.id)
            db.session.add(new_event)
            db.session.commit()

            # Add the event to Google Calendar
            event_body = {
                'summary': event_name,
                'start': {'dateTime': event_date_user_tz.isoformat(), 'timeZone': 'UTC'},
                'end': {'dateTime': event_date_user_tz.isoformat(), 'timeZone': 'UTC'},
                'reminders': {
                    'useDefault': False,
                    'overrides': []
                }
            }

            try:
                service.events().insert(calendarId='primary', body=event_body).execute()
                print(
                    f"Event '{event_name}' added to Google Calendar on {event_date_user_tz.isoformat()}")
            except HttpError as e:
                print(f"Error adding event '{event_name}': {str(e)}")


def select_word_document():
    root = tk.Tk()
    root.withdraw()

    file_path = filedialog.askopenfilename(
        title="Select Word Document",
        filetypes=[("Word Documents", "*.docx;*.doc")]
    )

    return file_path


if __name__ == "__main__":
    # Select Word document using a file dialog
    word_document_path = select_word_document()

    if word_document_path:
        # Extract events from the Word document
        events = extract_events_from_docx(word_document_path)

        if events:
            # Add events to Google Calendar
            add_events_to_calendar(events)
        else:
            print("No events found in the Word document.")
    else:
        print("No Word document selected.")
