app_name = "zatca2024"
app_title = "Zatca2024"
app_publisher = "ERPGulf"
app_description = "Saudi Zatca phase-2 implementation according to zatca 2024 documents"
app_email = "support@ERPGulf.com"
app_license = "mit"

from frappe import _
from . import __version__ as app_version
# import frappe

# required_apps = []

# Includes in <head>
# ------------------

# include js, css files in header of desk.html
# app_include_css = "/assets/zatca2024/css/zatca2024.css"
# app_include_js = "/assets/zatca2024/js/zatca2024.js"

# include js, css files in header of web template
# web_include_css = "/assets/zatca2024/css/zatca2024.css"
# web_include_js = "/assets/zatca2024/js/zatca2024.js"

# include custom scss in every website theme (without file extension ".scss")
# website_theme_scss = "zatca2024/public/scss/website"

# include js, css files in header of web form
# webform_include_js = {"doctype": "public/js/doctype.js"}
# webform_include_css = {"doctype": "public/css/doctype.css"}

# include js in page
# page_js = {"page" : "public/js/file.js"}

# include js in doctype views
# doctype_js = {"doctype" : "public/js/doctype.js"}
# doctype_list_js = {"doctype" : "public/js/doctype_list.js"}
# doctype_tree_js = {"doctype" : "public/js/doctype_tree.js"}
# doctype_calendar_js = {"doctype" : "public/js/doctype_calendar.js"}

# Svg Icons
# ------------------
# include app icons in desk
# app_include_icons = "zatca2024/public/icons.svg"

# Home Pages
# ----------

# application home page (will override Website Settings)
# home_page = "login"

# website user home page (by Role)
# role_home_page = {
#	"Role": "home_page"
# }

# Generators
# ----------

# automatically create page for each record of this doctype
# website_generators = ["Web Page"]

# Jinja
# ----------

# add methods and filters to jinja environment
# jinja = {
#	"methods": "zatca2024.utils.jinja_methods",
#	"filters": "zatca2024.utils.jinja_filters"
# }

# Installation
# ------------

# before_install = "zatca2024.install.before_install"
# after_install = "zatca2024.install.after_install"

# Uninstallation
# ------------

# before_uninstall = "zatca2024.uninstall.before_uninstall"
# after_uninstall = "zatca2024.uninstall.after_uninstall"

# Integration Setup
# ------------------
# To set up dependencies/integrations with other apps
# Name of the app being installed is passed as an argument

# before_app_install = "zatca2024.utils.before_app_install"
# after_app_install = "zatca2024.utils.after_app_install"

# Integration Cleanup
# -------------------
# To clean up dependencies/integrations with other apps
# Name of the app being uninstalled is passed as an argument

# before_app_uninstall = "zatca2024.utils.before_app_uninstall"
# after_app_uninstall = "zatca2024.utils.after_app_uninstall"

# Desk Notifications
# ------------------
# See frappe.core.notifications.get_notification_config

# notification_config = "zatca2024.notifications.get_notification_config"

# Permissions
# -----------
# Permissions evaluated in scripted ways

# permission_query_conditions = {
#	"Event": "frappe.desk.doctype.event.event.get_permission_query_conditions",
# }
#
# has_permission = {
#	"Event": "frappe.desk.doctype.event.event.has_permission",
# }

# DocType Class
# ---------------
# Override standard doctype classes

# override_doctype_class = {
#	"ToDo": "custom_app.overrides.CustomToDo"
# }

# Document Events
# ---------------
# Hook on document methods and events

# doc_events = {
#	"*": {
#		"on_update": "method",
#		"on_cancel": "method",
#		"on_trash": "method"
#	}
# }

# doc_events = {
    
#     "Sales Invoice": { "on_submit": [
#             "zatca2024.zatca2024.zatcasdkcode.before_save"
#          ]
#     }}


# Scheduled Tasks
# ---------------

# scheduler_events = {
#	"all": [
#		"zatca2024.tasks.all"
#	],
#	"daily": [
#		"zatca2024.tasks.daily"
#	],
#	"hourly": [
#		"zatca2024.tasks.hourly"
#	],
#	"weekly": [
#		"zatca2024.tasks.weekly"
#	],
#	"monthly": [
#		"zatca2024.tasks.monthly"
#	],
# }

# Testing
# -------

# before_tests = "zatca2024.install.before_tests"

# Overriding Methods
# ------------------------------
#
# override_whitelisted_methods = {
#	"frappe.desk.doctype.event.event.get_events": "zatca2024.event.get_events"
# }
#
# each overriding function accepts a `data` argument;
# generated from the base implementation of the doctype dashboard,
# along with any modifications made in other Frappe apps
# override_doctype_dashboards = {
#	"Task": "zatca2024.task.get_dashboard_data"
# }

# exempt linked doctypes from being automatically cancelled
#
# auto_cancel_exempted_doctypes = ["Auto Repeat"]

# Ignore links to specified DocTypes when deleting documents
# -----------------------------------------------------------

# ignore_links_on_delete = ["Communication", "ToDo"]

# Request Events
# ----------------
# before_request = ["zatca2024.utils.before_request"]
# after_request = ["zatca2024.utils.after_request"]

# Job Events
# ----------
# before_job = ["zatca2024.utils.before_job"]
# after_job = ["zatca2024.utils.after_job"]

# User Data Protection
# --------------------

# user_data_fields = [
#	{
#		"doctype": "{doctype_1}",
#		"filter_by": "{filter_by}",
#		"redact_fields": ["{field_1}", "{field_2}"],
#		"partial": 1,
#	},
#	{
#		"doctype": "{doctype_2}",
#		"filter_by": "{filter_by}",
#		"partial": 1,
#	},
#	{
#		"doctype": "{doctype_3}",
#		"strict": False,
#	},
#	{
#		"doctype": "{doctype_4}"
#	}
# ]

# Authentication and authorization
# --------------------------------

# auth_hooks = [
#	"zatca2024.auth.validate"
# ]

# Automatically update python controller files with type annotations for this app.
# export_python_type_annotations = True

# default_log_clearing_doctypes = {
#	"Logging DocType Name": 30  # days to retain logs
# }
doc_events = {
    "Sales Invoice": {
        # "before_submit": "zatca2024.zatca2024.validations.zatca_done_or_not",
        # "before_save": "zatca2024.zatca2024.validations.before_save",
        "before_cancel": "zatca2024.zatca2024.validations.before_save",
        "after_insert": "zatca2024.zatca2024.validations.duplicating_invoice",
        "on_submit": "zatca2024.zatca2024.zatcasdkcode.zatca_Background_on_submit"
    }
}
doctype_js = {
    "Sales Invoice" : "public/js/our_sales_invoice.js" ,
    }


fixtures = [ {"dt": "Custom Field","filters": [["module", "=", "zatca2024"]] }]