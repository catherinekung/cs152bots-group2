import re
from enum import Enum, auto
import json

from discord.components import SelectOption
from discord.ui import Select, View

FAKE_DB = "fake_db.json"


class State(Enum):
    AWAITING_MESSAGE = auto()
    RULES_START = auto()
    RULES_CONTINUE = auto()
    RULE_CREATE = auto()
    RULE_EDIT = auto()
    RULES_DELETE = auto()
    RULES_SET = auto()


class UserRules:
    START_KEYWORD = "rules"
    HELP_KEYWORD = "help"
    CANCEL_KEYWORD = "cancel"

    def __init__(self, client):
        self.client = client
        self.user = None
        self._db = self._get_db()
        self.user_flags = None
        self.flags = self._get_flags()  # flag words from all users (not a good way to do this in real life)
        self.state = State.RULES_SET

    @staticmethod
    def _get_db() -> dict:
        with open(FAKE_DB, "r") as f:
            db = json.load(f)

        return db

    def _write_db(self):
        with open(FAKE_DB, "w") as f:
            f.write(json.dumps(self._db, indent=2))

        return True

    def _get_flags(self, for_user: bool = False) -> list:
        if for_user:
            return list(set(self._db.get(self.user, {}).get("rules", [])))  # get rid of duplicates

        flags = []
        for user in self._db.values():
            flags.extend(user["rules"])

        return list(set(flags))  # get rid of duplicates

    def get_rules_view(self):
        options = [
            SelectOption(emoji="➕", label='Add a Rule', value='add',
                         description="You can add a new word to flag"),
        ]

        if self.user_flags:
            options += [SelectOption(emoji="🔧", label='Edit a Rule', value='edit',
                                     description="Edit a previously added rule"),
                        SelectOption(emoji="🚮", label='Delete a Rule', value='delete',
                                     description="Delete a previously added rule"),
                        ]

        dropdown = Select(
            placeholder='Select an option',
            options=options,
            custom_id='rule_dropdown'
        )

        async def callback(interaction):
            if dropdown.values[0] == 'add':
                self.state = State.RULE_CREATE
                await interaction.response.send_message(
                    f"What word or phrase would you like to flag from the discord channel?")
            elif dropdown.values[0] == 'edit':
                self.state = State.RULE_EDIT
                await interaction.response.send_message(f"Please select the rule you would like to edit",
                                                        view=self.get_edit_view())
            elif dropdown.values[0] == "delete":
                self.state = State.RULES_DELETE
                await interaction.response.send_message(f"Please select the rule you would like to delete",
                                                        view=self.get_delete_view())

        dropdown.callback = callback
        view = View()
        view.add_item(dropdown)
        return view

    def get_delete_view(self):
        options = []
        self.user_flags = self._get_flags(for_user=True)
        for flag in self.user_flags:
            options.append(SelectOption(emoji="🚮", label=flag, value=flag,
                                        description=f"Delete '{flag}' from your rules"))

        dropdown = Select(
            placeholder='Select the rule you want to delete',
            options=options,
            custom_id='delete_dropdown'
        )

        async def callback(interaction):
            self._db[self.user]["rules"].remove(dropdown.values[0])
            self._write_db()
            self.user_flags = self._get_flags(for_user=True)
            self.flags = self._get_flags(for_user=False)
            self.state = State.RULES_SET
            await interaction.response.send_message(
                f"The rule for '{dropdown.values[0]}' has been deleted")

        dropdown.callback = callback
        view = View()
        view.add_item(dropdown)
        return view

    def get_edit_view(self):
        options = []
        for flag in self.user_flags:
            options.append(SelectOption(emoji="🔧", label=flag, value=flag,
                                        description=f"Edit '{flag}'"))

        dropdown = Select(
            placeholder='Select which rule you would like to edit',
            options=options,
            custom_id='edit_dropdown'
        )

        async def callback(interaction):
            # for simplicity, just delete the rule and add a new one
            self._db[self.user]["rules"].remove(dropdown.values[0])
            self.user_flags = self._get_flags(for_user=True)
            self.flags = self._get_flags(for_user=False)

            self.state = State.RULE_EDIT
            await interaction.response.send_message(
                f"What would you like to update '{dropdown.values[0]}' to?")

        dropdown.callback = callback
        view = View()
        view.add_item(dropdown)
        return view

    async def handle_message(self, message):
        print(f"{message.content = } {self.state = }")
        if message.content == self.CANCEL_KEYWORD:
            print("message.content == self.CANCEL_KEYWORD")
            self.state = State.RULES_SET
            return [{"response": "Rule creation cancelled."}]

        if self.state == State.RULES_START:
            print("self.state == State.RULES_START")
            reply = "Thank you for starting the rule creation process. "
            self.state = State.RULES_CONTINUE
            return [{"response": reply, "view": self.get_rules_view()}]

        if self.state == State.RULE_CREATE or self.state == State.RULE_EDIT:
            if message.content in self.user_flags:
                self.state = State.RULES_SET
                return [{"response": f"Rule for '{message.content}' is already in rules."}]
            self.user_flags.append(message.content)
            if self._db.get(self.user):
                if self._db[self.user].get("rules"):
                    self._db[self.user]["rules"].append(message.content)
                else:
                    self._db[self.user]["rules"] = [message.content]
            else:
                self._db[self.user] = {"rules": [message.content]}
            self._write_db()
            if self.state == State.RULE_CREATE:
                response = f"Rule for '{message.content}' created."
            else:
                response = f"Rule for '{message.content}' has been updated."

            self.state = State.RULES_SET
            return [{"response": response}]

    def rules_complete(self) -> bool:
        return self.state == State.RULES_SET

    def update_rules(self, user: str) -> None:
        self.user = str(user)
        self.user_flags = self._get_flags(for_user=True)
        if self.state == State.RULES_SET:
            self.state = State.RULES_START

    def get_rules_scores(self, message: str) -> dict:
        # Create a regex pattern that matches any of the phrases
        pattern = '|'.join(re.escape(phrase) for phrase in self.flags)
        # Search for the pattern in the sentence
        matches = re.findall(pattern, message, re.IGNORECASE)
        if matches:
            return {"rules": matches}
        return {}

    def get_user_offenses(self, user):
        user = str(user)
        if user in self._db:
            if self._db[user].get("offenses"):
                return self._db[user].get("offenses")
            return 0
        return 0

    def update_user_offenses(self, user):
        user = str(user)
        if user in self._db:
            if self._db[user].get("offenses"):
                self._db[user]["offenses"] += 1
            else:
                self._db[user]["offenses"] = 1
        else:
            self._db[user] = {"offenses": 1}
        self._write_db()



if __name__ == "__main__":
    bot = UserRules("hi")
    print(f'{bot.get_rules_scores("Im going to get you") = }')
    print(f'{bot.get_rules_scores("Youre a good guy") = }')
    print(f'{bot.get_rules_scores("You cash now have your money") = }')
    print(f'{bot.get_rules_scores("money") = }')
    print(f'{bot.get_rules_scores("I love me some cash") = }')
    print(f'{bot.get_rules_scores("I love me some crypto") = }')
