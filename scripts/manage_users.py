import argparse
import getpass
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from app import auth, config, models
from app.db import init_db, session_scope

DEMO_ACCOUNTS = [
    ("admin@demo.local", "admin", "Demo Admin"),
    ("reviewer@demo.local", "reviewer", "Demo Reviewer"),
    ("merchant@demo.local", "merchant", "Demo Merchant"),
]


def _actor_label() -> str:
    try:
        return f"cli:{getpass.getuser()}"
    except Exception:
        return "cli"


def _read_new_password(arguments) -> str:
    if arguments.password_stdin:
        return sys.stdin.readline().rstrip("\n")
    first_entry = getpass.getpass("New password: ")
    if getpass.getpass("Repeat password: ") != first_entry:
        raise auth.AuthError("The two passwords do not match.")
    return first_entry


def command_list(_arguments):
    with session_scope() as session:
        users = session.query(models.User).order_by(models.User.id).all()
        print(f"{'id':>4}  {'email':<34} {'role':<9} {'status':<9} last login")
        for user in users:
            last_login = user.last_login_at.isoformat(timespec="minutes") if user.last_login_at else "never"
            status = "disabled" if user.disabled else "active"
            print(f"{user.id:>4}  {user.email:<34} {user.role:<9} {status:<9} {last_login}")


def command_create(arguments):
    password = _read_new_password(arguments)
    with session_scope() as session:
        user = auth.create_user(session, arguments.email, password, arguments.role, arguments.name or "", consent=False)
        print(f"created {user.role} {user.email} (id {user.id})")


def command_disable(arguments):
    with session_scope() as session:
        user = auth.user_by_email(session, arguments.email)
        ended_sessions = auth.set_user_disabled(session, user, True, _actor_label())
        print(f"disabled {user.email}; {ended_sessions} active session(s) ended")


def command_enable(arguments):
    with session_scope() as session:
        user = auth.user_by_email(session, arguments.email)
        auth.set_user_disabled(session, user, False, _actor_label())
        print(f"enabled {user.email}")


def command_set_role(arguments):
    with session_scope() as session:
        user = auth.user_by_email(session, arguments.email)
        auth.change_role(session, user, arguments.role, _actor_label())
        print(f"{user.email} is now {user.role}")


def command_reset_password(arguments):
    with session_scope() as session:
        auth.user_by_email(session, arguments.email)
    password = _read_new_password(arguments)
    with session_scope() as session:
        user = auth.user_by_email(session, arguments.email)
        auth.reset_password(session, user, password, _actor_label())
        print(f"password reset for {user.email}; all their sessions were ended")


def command_seed_demo(_arguments):
    with session_scope() as session:
        for email, role, full_name in DEMO_ACCOUNTS:
            try:
                auth.create_user(session, email, config.DEMO_PASSWORD, role, full_name, consent=True)
                print(f"created {role:<9} {email}")
            except auth.AuthError:
                print(f"exists  {role:<9} {email}")
    print(f"(demo password: {config.DEMO_PASSWORD}; development only)")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Manage user accounts.", epilog=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("list", help="list all accounts").set_defaults(handler=command_list)
    create_parser = commands.add_parser("create", help="create an account")
    create_parser.add_argument("email")
    create_parser.add_argument("role", choices=auth.ALL_ROLES)
    create_parser.add_argument("--name", default="")
    create_parser.add_argument("--password-stdin", action="store_true")
    create_parser.set_defaults(handler=command_create)
    for command_name, handler, help_text in (("disable", command_disable, "block login and end all sessions"),
                                             ("enable", command_enable, "allow login again")):
        simple_parser = commands.add_parser(command_name, help=help_text)
        simple_parser.add_argument("email")
        simple_parser.set_defaults(handler=handler)
    role_parser = commands.add_parser("set-role", help="change an account's role")
    role_parser.add_argument("email")
    role_parser.add_argument("role", choices=auth.ALL_ROLES)
    role_parser.set_defaults(handler=command_set_role)
    password_parser = commands.add_parser("reset-password", help="set a new password and end all sessions")
    password_parser.add_argument("email")
    password_parser.add_argument("--password-stdin", action="store_true")
    password_parser.set_defaults(handler=command_reset_password)
    commands.add_parser("seed-demo", help="create the demo accounts (development only)").set_defaults(
        handler=command_seed_demo)
    return parser


def main(argv: list[str] | None = None) -> int:
    arguments = build_parser().parse_args(argv)
    init_db()
    try:
        arguments.handler(arguments)
    except auth.AuthError as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
