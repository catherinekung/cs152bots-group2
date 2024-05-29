import asyncio

import discord
from discord.ext import commands
import os
import json
import logging
import re
import requests

from user_rules import UserRules
from scam_classifier import ScamClassier
from report import Report
from discord.components import SelectOption
from discord.ui import Select, View, Button
from datetime import datetime
import re
from suspicious_link_detection import identify_suspicious_links

# Set up logging to the console
logger = logging.getLogger('discord')
logger.setLevel(logging.DEBUG)
handler = logging.FileHandler(filename='discord.log', encoding='utf-8', mode='w')
handler.setFormatter(logging.Formatter('%(asctime)s:%(levelname)s:%(name)s: %(message)s'))
logger.addHandler(handler)

# There should be a file called 'tokens.json' inside the same folder as this file
token_path = 'tokens.json'
if not os.path.isfile(token_path):
    raise Exception(f"{token_path} not found!")
with open(token_path) as f:
    # If you get an error here, it means your token is formatted incorrectly. Did you put it in quotes?
    tokens = json.load(f)
    discord_token = tokens['discord']
    virus_total_token = tokens['virus_total']

def predetermine_action(report_reason, user_client, user):
    actions = {"Ban User": False, "Remove Post": False, "Report User to Discord": False, "Place User on Probation": False}
    if "Blackmail" in report_reason:
        if "Explicit Content" in report_reason or "Threat to do Physical Harm" in report_reason or "Personal/Sensitive Information" in report_reason:
            actions['Remove Post'] = True
        if "Threat to do Physical Harm" in report_reason or "Personal/Sensitive Information" in report_reason:
            actions["Ban User"] = True
        if "Threat to do Physical Harm" in report_reason:
            actions["Report User to Discord"] = True
    elif "Investment Scam" in report_reason:
        actions['Remove Post'] = True
        actions["Ban User"] = True
        if "Assets Sent" in report_reason or "Suspicion of Impersonation" in report_reason:
            actions["Report User to Discord"] = True
    elif "Suspicious Link" in report_reason:
        actions['Remove Post'] = True
        if user_client.get_user_offenses(user) >= 2:
            actions["Ban User"] = True
        else:
            actions["Place User on Probation"] = True
    elif "Imminent Danger" in report_reason:
        actions['Remove Post'] = True
        actions["Ban User"] = True
        actions["Report User to Discord"] = True

    return actions

class ModeratorActionDropdown(Select):
    def __init__(self, mod_channel, reported_message, user_client):
        super().__init__(placeholder="What actions do you want to take?", min_values=1, max_values=4)
        self.mod_channel = mod_channel
        self.reported_message = reported_message
        self.user_client = user_client
        actions = predetermine_action(reported_message.get("report_reason"), self.user_client, self.reported_message.get("message").author.id)
        self.add_option(default=actions["Ban User"], label="Ban User", description="Ban the actor from the server", value="Actor has been banned")
        self.add_option(default=actions["Remove Post"], label="Remove Post", description="Remove the post from the channel", value="Post has been removed")
        self.add_option(default=actions["Report User to Discord"], label="Report User to Discord", description="Report the User to Discord", value="Actor has been reported to Discord")
        self.add_option(default=actions["Place User on Probation"], label="Place User on Probation", description="Place the actor on temporary probation", value="Actor has been placed on temporary probation")
        self.add_option(label="No action required", description="Report was false or no action needed", value="No action taken")

    async def callback(self, interaction):
        self.user_client.update_user_offenses(self.reported_message.get("message").author.id)
        if "Actor has been banned" in self.values:
            await self.reported_message.get("message").author.send("You have been banned from the Trust and Safety - Spring 2024 server.")
        elif "Actor has been placed on temporary probation" in self.values:
            await self.reported_message.get("message").author.send("Your account has been put on temporary probabtion and will have limited access to features due to policy violations.")
        if self.values[0] == "No action required":
            action_status = "No actions were taken. Thank you for moderating this report!"
        else:
            action_status = f'Actions taken: {", ".join(self.values)}. Thank you for moderating this report!'
        await self.mod_channel.send(action_status)
        await interaction.response.defer()

class ConfirmButton(Button):
    def __init__(self, mod_channel, reported_message, user_client):
        super().__init__(label="Confirm Action(s)")
        self.mod_channel = mod_channel
        self.reported_message = reported_message
        self.user_client = user_client
        self.actions = predetermine_action(reported_message.get("report_reason"), self.user_client, self.reported_message.get("message").author.id)

    async def callback(self, interaction):
        self.user_client.update_user_offenses(self.reported_message.get("message").author.id)
        action_str = {"Ban User": "Actor has been banned", "Remove Post": "Post has been removed", "Report User to Discord": "Actor has been reported to Discord", "Place User on Probation": "Actor has been placed on temporary probation"}
        if self.actions["Ban User"]:
            await self.reported_message.get("message").author.send(
                "You have been banned from the Trust and Safety - Spring 2024 server.")
        elif self.actions["Place User on Probation"]:
            await self.reported_message.get("message").author.send(
                "Your account has been put on temporary probabtion and will have limited access to features due to policy violations.")
        values = [action_str[action] for action in self.actions if self.actions[action]]
        action_status = f'Actions taken: {", ".join(values)}. Thank you for moderating this report!'
        await self.mod_channel.send(action_status)
        await interaction.response.defer()
    
class LegitimacyDropdown(Select):
    def __init__(self, mod_channel, reported_message, user_client):
        super().__init__(placeholder="Select one", min_values=1, max_values=1)
        self.mod_channel = mod_channel
        self.reported_message = reported_message
        self.user_client = user_client
        self.add_option(label="Yes", description="The report reason is appropriate", value="legitimate")
        self.add_option(label="No, revision required", description="The report reason needs to be revised", value="update required")
        self.add_option(label="No, false report", description="The content was falsely reported", value="not legitimate")

    async def callback(self, interaction):
        await interaction.response.defer()
        if self.values[0] == 'not legitimate':
            await self.mod_channel.send("The content was falsely reported. No further action is required. Thank you for moderating this report!")
        else:
            if self.values[0] == "update required":
                prompt_message = "\n\nPlease specify the appropriate abuse type"
                await self.mod_channel.send(prompt_message)
                message = await interaction.client.wait_for_report_reason_update(self.mod_channel, interaction.user)
                self.reported_message["report_reason"] = message
            else:
                await self.mod_channel.send("\nReport reason is confirmed.")
                if "Imminent Danger" in self.reported_message.get("report_reason") or "Threat to do Physical Harm" in self.reported_message.get("report_reason") or "Assets Sent" in self.reported_message.get("report_reason"):
                    prompt_message = "\n\nPlease type a message that can be sent to the authorities regarding this case."
                    await self.mod_channel.send(prompt_message)
                    await interaction.client.wait_for_user_reply(self.mod_channel, interaction.user, f"Thank you for your response, {interaction.user}. A report has been filed with the authorities. Please wait for further instructions.")
                elif "Suspicious Link" in self.reported_message.get("report_reason"):
                    scores = interaction.client.eval_text(self.reported_message.get("message").content)
                    await interaction.client.handle_malicious_link(self.reported_message.get("message").content, scores, self.mod_channel, False)
            if not "Suspicious Link" in self.reported_message.get("report_reason"):
                view = View()
                view.add_item(ModeratorActionDropdown(self.mod_channel, self.reported_message, self.user_client))
                view.add_item(ConfirmButton(self.mod_channel, self.reported_message, self.user_client))
                await self.mod_channel.send("\n\nPlease select the action(s) you want to take. If you would like to proceed with the preselected, recommended actions, press 'Confirm Action(s)'. If not, please update the selection of appropriate actions.", view=view)

class MaliciousLinkDropdown(Select):
    def __init__(self, mod_channel, reported_message, user_client):
        super().__init__(placeholder="Is the link malicious?", min_values=1, max_values=1)
        self.mod_channel = mod_channel
        self.reported_message = reported_message
        self.user_client = user_client
        self.add_option(label="Yes", description="The link is malicious", value="yes")
        self.add_option(label="No", description="The link is not malicious", value="no")

    async def callback(self, interaction):
        await interaction.response.defer()
        action_message = "\n\nPlease select the action(s) you want to take. If you would like to proceed with the preselected, recommended actions, press 'Confirm Action(s)'. If not, please update the selection of appropriate actions."
        view = View()
        view.add_item(ModeratorActionDropdown(self.mod_channel, self.reported_message, self.user_client))
        view.add_item(ConfirmButton(self.mod_channel, self.reported_message, self.user_client))
        if self.values[0] == 'yes':
            await self.mod_channel.send(
                "Link is marked as malicious and has been added to our internal blacklist." + action_message,
                view=view)
        else:
            await self.mod_channel.send(
                "Link was deemed not malicious. No further action is required. Thank you for moderating this report!")


class ReportReasonDropdown(Select):
    def __init__(self, mod_channel, reported_message):
        options = [
            SelectOption(emoji="📫", label='Blackmail', value='Blackmail',
                         description="You are being threatened to send cryptocurrency"),
            SelectOption(emoji="💰", label='Investment Scam', value='Investment Scam',
                         description="You sent cryptocurrency to a fraudulent individual"),
            SelectOption(emoji="🔗", label='Suspicious Link', value='Suspicious Link',
                         description="You received a link that may lead to a disreputable site"),
            SelectOption(emoji="⚠️", label="Imminent Danger", value="Imminent Danger",
                         description="You are in immediate danger"),
            SelectOption(emoji="❓", label="Other", value="Other",
                         description="You have a different reason for reporting")
        ]
        super().__init__(placeholder='Update the reporting reason', min_values=1, max_values=1, options=options)
        self.mod_channel = mod_channel
        self.reported_message = reported_message

    async def callback(self, interaction):
        report_status = f'Report reason has been updated to: {self.values[0]}'
        await self.mod_channel.send(report_status)
        await interaction.response.defer()
        if "Imminent Danger" in self.reported_message.get(
                "report_reason") or "Threat to do Physical Harm" in self.reported_message.get(
                "report_reason") or "Assets Sent" in self.reported_message.get("report_reason"):
            prompt_message = "Please type a message that can be sent to the authorities regarding this case."
            await self.mod_channel.send(prompt_message)
            await interaction.client.wait_for_user_reply(self.mod_channel, interaction.user,
                                                         f"Thank you for your response, {interaction.user}. A report has been filed with the authorities. Please wait for further instructions.")

        action_view = View()
        action_view.add_item(ModeratorActionDropdown(self.mod_channel, self.reported_message))
        await self.mod_channel.send(
            "\n\nPlease select the action(s) you want to take. If you would like to proceed with the preselected, recommended actions, press 'Confirm Action(s)'. If not, please update the selection of appropriate actions.",
            view=action_view)



def create_legitimacy_view(mod_channel, reported_message, user_client):
    view = View()
    view.add_item(LegitimacyDropdown(mod_channel, reported_message, user_client))
    return view


class ModBot(discord.Client):
    def __init__(self):
        intents = discord.Intents.default()
        intents.message_content = True
        super().__init__(command_prefix='.', intents=intents)
        self.group_num = None
        self.mod_channels = {}  # Map from guild to the mod channel id for that guild
        self.reports = {}  # Map from user IDs to the state of their report
        self.user_rules = UserRules(self)
        self.reported_message = None
        self.scam_classifier = ScamClassier()

    async def on_ready(self):
        print(f'{self.user.name} has connected to Discord! It is these guilds:')
        for guild in self.guilds:
            print(f' - {guild.name}')
        print('Press Ctrl-C to quit.')

        # Parse the group number out of the bot's name
        match = re.search('[gG]roup (\d+) [bB]ot', self.user.name)
        if match:
            self.group_num = match.group(1)
        else:
            raise Exception("Group number not found in bot's name. Name format should be \"Group # Bot\".")

        for guild in self.guilds:
            for channel in guild.text_channels:
                if channel.name == f'group-{self.group_num}-mod':
                    self.mod_channels[guild.id] = channel
                    
    async def wait_for_user_reply(self, channel, user, reply=None):
        def check(m):
            return m.author == user and m.channel == channel

        try:
            message = await self.wait_for('message', check=check, timeout=300)
            if reply:
                await channel.send(reply)
            else:
                return message.content
        except asyncio.TimeoutError:
            await channel.send("You did not respond in time.")

    async def wait_for_report_reason_update(self, channel, user):
        priorities = {"Assets Sent": 2, "Personal Information Provided": 2, "Suspicion of Impersonation": 3,
                    "Explicit Content": 3, "Personal/Sensitive Information": 2, "Threat to do Physical Harm": 1,
                    "Suspicious Link": 4, "Imminent Danger": 1, "Other": "TBD"}
        def check(m):
            return m.author == user and m.channel == channel

        try:
            message = await self.wait_for('message', check=check, timeout=300)
            if message.content not in priorities:
                values = message.content.split(" - ")[1].split(", ")
            else:
                values = [message.content]
            priority = min([priorities[v] for v in values])
            priority_colors = ["🔴", "🟠", "🟡", "🟢", "⚪️"]
            await channel.send(f"* Report reason has been updated: {message.content}\n* Priority: P{priority} {priority_colors[priority-1]}")
            return message.content
        except asyncio.TimeoutError:
            await channel.send("You did not respond in time.")

    async def on_message(self, message):
        '''
        This function is called whenever a message is sent in a channel that the bot can see (including DMs). 
        Currently the bot is configured to only handle messages that are sent over DMs or in your group's "group-#" channel. 
        '''
        # Ignore messages from the bot 
        if message.author.id == self.user.id:
            return
        # Check if this message was sent in a server ("guild") or if it's a DM
        if message.guild:
            await self.handle_channel_message(message)
        else:
            await self.handle_dm(message)

    async def handle_dm(self, message):
        # Handle a help message
        if message.content == Report.HELP_KEYWORD:
            reply = "Use the `report` command to begin the reporting process.\n"
            reply += "User the `rules` command to begin the rule creation process.\n"
            reply += "Use the `cancel` command to cancel the report process.\n"
            await message.channel.send(reply)
            return

        author_id = message.author.id
        responses = []

        reporting = (author_id in self.reports
                     or message.content.startswith(Report.START_KEYWORD))
        creating_rules = (not self.user_rules.rules_complete()
                          or message.content.startswith(UserRules.START_KEYWORD))

        # Only respond to messages if they're part of a reporting flow
        if not reporting and not creating_rules:
            return

        if reporting:
            # If we don't currently have an active report for this user, add one
            if author_id not in self.reports:
                self.reports[author_id] = Report(self)

            # Let the report class handle this message; forward all the messages it returns to uss
            responses = await self.reports[author_id].handle_message(message)
            for r in responses:
                await message.channel.send(r.get("response"), view=r.get("view"))
                if r.get("summary"):
                    self.reported_message = {"message": r.get("reported_message"), "priority": r.get("priority"), "report_reason": r.get("reported_reason"), "automated": False}
                    mod_channel = self.mod_channels[r.get("reported_message").guild.id]
                    view = create_legitimacy_view(mod_channel, self.reported_message, self.user_rules)
                    offenses = self.user_rules.get_user_offenses(r.get("reported_message").author.id)
                    await mod_channel.send(r.get("summary") + f"\n* {r.get('reported_message').author.name} has had {offenses} reports made against them\n\nIs the report reason appropriate for the reported content?", view=view)

            # If the report is complete or cancelled, remove it from our map
            if self.reports[author_id].report_complete():
                self.reports.pop(author_id)

        elif creating_rules:
            self.user_rules.update_rules(user=author_id)
            responses = await self.user_rules.handle_message(message)
            for r in responses:
                await message.channel.send(r.get("response"), view=r.get("view"))

    async def handle_malicious_link(self, message, scores, mod_channel, automated=True):
        if -1 not in scores['suspicious_link'].values():
            action_view = View()
            action_view.add_item(ModeratorActionDropdown(mod_channel, self.reported_message, self.user_rules))
            action_view.add_item(ConfirmButton(mod_channel, self.reported_message, self.user_rules))
            action_message = "\n\nPlease select the action(s) you want to take. If you would like to proceed with the preselected, recommended actions, press 'Confirm Action(s)'. If not, please update the selection of appropriate actions."

            await mod_channel.send(self.code_format(scores, message, automated) + action_message, view=action_view)
        else:
            malicious_view = View()
            malicious_view.add_item(MaliciousLinkDropdown(mod_channel, self.reported_message, self.user_rules))
            await mod_channel.send(
                self.code_format(scores, message, automated) + "\nPlease review the reported link. Is it malicious?",
                view=malicious_view)

    async def handle_channel_message(self, message):
        # Only handle messages sent in the "group-#" channel
        if not message.channel.name == f'group-{self.group_num}':
            return

        # Forward the message to the mod channel
        mod_channel = self.mod_channels[message.guild.id]
        scores = self.eval_text(message.content)
        if scores:
            if 'suspicious_link' in scores:
                self.reported_message = {"message": message, "priority": 4,
                                         "report_reason": "Suspicious Link", "automated": True}
                await self.handle_malicious_link(message, scores, mod_channel)
                await message.channel.send(
                    "🚨 The above content has been removed as it contains a suspicious link. If you believe this to be in error, please __submit your feedback__. 🚨")

            elif 'scam' in scores and scores['scam'] == 1:
                self.reported_message = {"message": message, "priority": 3,
                                         "report_reason": "Suspected Cryptocurrency Scam", "automated": True}
                action_view = View()
                action_view.add_item(ModeratorActionDropdown(mod_channel, self.reported_message, self.user_rules))
                await mod_channel.send(self.code_format(scores, message), view=action_view)
                await message.channel.send(
                    "🚨 The above content has been removed as it violates our policies on cryptocurrency. If you believe this to be in error, please __submit your feedback__. 🚨")
            else:
                await mod_channel.send(self.code_format(scores, message))
                await message.channel.send(
                    "🚨 The above content has been removed as it violates our community guidelines. If you believe this to be in error, please __submit your feedback__. 🚨")


    def eval_text(self, message):
        ''''
        TODO: Once you know how you want to evaluate messages in your channel, 
        insert your code here! This will primarily be used in Milestone 3. 
        '''
        all_scores = {}
        # Automated flagging for suspicious links
        scores = identify_suspicious_links(message, virus_total_token)
        if len(scores) > 0:
            if -1 in scores.values() or 1 in scores.values():
                all_scores['suspicious_link'] = scores

        # Automated flagging for community specified rules
        rules_scores = self.user_rules.get_rules_scores(message)
        if rules_scores.get("rules"):
            all_scores['rules'] = rules_scores['rules']

        # Automated flagging for potential scams
        is_scam = self.scam_classifier.predict_scam(message)
        all_scores['scam'] = is_scam

        if len(all_scores) > 0:
            return all_scores
        return None

    def code_format(self, scores, message, automated=True):
        ''''
        TODO: Once you know how you want to show that a message has been
        evaluated, insert your code here for formatting the string to be
        shown in the mod channel.
        '''
        '''
        1 = automated report created, no action needed from moderators
        0 = no report required
        -1 = automated report created, action needed from moderators
        '''
        date = datetime.today().strftime("%B %d, %Y")
        if 'suspicious_link' in scores:
            url_scores = scores['suspicious_link']
            urls_requiring_manual_review = [url for url in url_scores if url_scores[url] == -1]
            urls_auto_flagged = [url for url in url_scores if url_scores[url] == 1]
            return_message = ""
            if automated:
                return_message = f"An automated report was filed on {date} on the following message: \n```{message.author.name}: {message.content}```\n* Report reason: Suspicious Link \n* Priority: 🟢"
            if len(urls_auto_flagged) > 0:
                return_message += f"\n* The following links were verified as malicious = {','.join(urls_auto_flagged)}."

            if len(urls_requiring_manual_review) > 0:
                return_message += f"\n* The following links require manual review = {','.join(urls_requiring_manual_review)}."
            return return_message
        
        if 'rules' in scores and len(scores['rules']) > 0:
            phrases_found = ", ".join(scores['rules'])
            return (f"The following message was automatically flagged and deleted: \n```{message.author.name}: {message.content}```\n"
                    f"This is due to containing the following phrase(s): {phrases_found}")

        if "scam" in scores and scores['scam'] == 1:
            return_message = f"An automated report was filed on {date} on the following message: \n```{message.author.name}: {message.content}```\n* Report reason: Suspected Cryptocurrency Scam \n* Priority: 🟡\n\nPlease determine if this a scam and determine the appropriate actions, if required."
            return return_message
        return ""

client = ModBot()
client.run(discord_token)
