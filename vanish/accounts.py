"""Direct deletion / deactivation links and steps for major accounts.

These are your own accounts. vanish only points you at the official flows;
it never logs in or acts on your behalf.
"""

ACCOUNTS = [
    {
        "id": "instagram",
        "name": "Instagram",
        "url": "https://www.instagram.com/accounts/remove/request/permanent/",
        "steps": [
            "Log in, then open the delete-account page above.",
            "Pick a reason and re-enter your password.",
            "Account is queued for deletion and fully removed after 30 days.",
        ],
    },
    {
        "id": "facebook",
        "name": "Facebook",
        "url": "https://www.facebook.com/help/delete_account",
        "steps": [
            "Settings & privacy > Settings > Your Facebook information.",
            "Choose 'Deactivation and deletion' > 'Delete account'.",
            "Confirm with your password; 30-day grace period before erasure.",
        ],
    },
    {
        "id": "x",
        "name": "X (Twitter)",
        "url": "https://twitter.com/settings/deactivate",
        "steps": [
            "Settings > Your account > Deactivate your account.",
            "Confirm deactivation with your password.",
            "Data is deleted after 30 days unless you log back in.",
        ],
    },
    {
        "id": "tiktok",
        "name": "TikTok",
        "url": "https://www.tiktok.com/setting/account",
        "steps": [
            "Profile > Menu > Settings and privacy > Account.",
            "Tap 'Deactivate or delete account' and follow prompts.",
            "30-day deactivation window precedes permanent deletion.",
        ],
    },
    {
        "id": "linkedin",
        "name": "LinkedIn",
        "url": "https://www.linkedin.com/psettings/account-management/close-submit",
        "steps": [
            "Me > Settings & Privacy > Account preferences.",
            "Under 'Account management' choose 'Close account'.",
            "Pick a reason and confirm with your password.",
        ],
    },
    {
        "id": "reddit",
        "name": "Reddit",
        "url": "https://www.reddit.com/settings/account",
        "steps": [
            "Open account settings (link above).",
            "Scroll to the bottom and click 'Delete account'.",
            "Re-enter username/password to confirm; deletion is permanent.",
        ],
    },
    {
        "id": "snapchat",
        "name": "Snapchat",
        "url": "https://accounts.snapchat.com/accounts/delete_account",
        "steps": [
            "Open the account portal link and sign in.",
            "Confirm deletion of your account.",
            "Account is deactivated 30 days, then permanently deleted.",
        ],
    },
    {
        "id": "google-account",
        "name": "Google Account",
        "url": "https://myaccount.google.com/delete-services-or-account",
        "steps": [
            "Choose 'Delete your Google Account' (or a single service).",
            "Review/download your data via Google Takeout first.",
            "Re-enter your password and confirm the deletion.",
        ],
    },
    {
        "id": "google-results-about-you",
        "name": "Google 'Results about you'",
        "url": "https://myactivity.google.com/results-about-you",
        "steps": [
            "Open the 'Results about you' tool and sign in.",
            "Add the contact info you want monitored (name, phone, address).",
            "Request removal of Search results that expose that info, and",
            "Enable alerts so you're notified when new results appear.",
        ],
    },
]


def all_accounts():
    return ACCOUNTS
