# synapse-simple-antispam
A simple spam checker module for Synapse to block invites from unwanted homeservers


## Installation

In your Synapse python environment:
```bash
pip install git+https://github.com/toshanmugaraj/Antispam.git
```

Then add to your `homeserver.yaml`:
```yaml
spam_checker:
  # Module to block invites from listed homeservers
  - module: "synapse_simple_antispam.AntiSpamInvites"
      groups:
        Group1:
          Normal:
            - "user1"
            - "user2"
          Restricted:
            - "user3"
            - "user4"
            - "user5" 
          allow_within_group: true
        Group2:
          Normal:
            - "user6"
            - "user7"
          Restricted:
            - "user8"
            - "user9"
            - "user10"   
```

Synapse will need to be restarted to apply the changes. To modify the list of homeservers,
update the config and restart Synapse.
