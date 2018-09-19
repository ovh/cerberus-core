
from .actions import CDNRequestActions, EmailReplyActions, ReportActions
from .variables import CDNRequestVariables, EmailReplyVariables, ReportVariables


def setup_business_rule_engine(app):

    try:
        variables = app.config["RULES"]["variables"]
        app.logger.info("Registering variables {}".format(variables))

        EmailReplyVariables.set_up(variables["emailreply"])
        CDNRequestVariables.set_up(variables["cdnrequest"])
        ReportVariables.set_up(variables["report"])

        actions = app.config["RULES"]["actions"]
        app.logger.info("Registering actions {}".format(actions))

        EmailReplyActions.set_up(actions["emailreply"])
        CDNRequestActions.set_up(actions["cdnrequest"])
        ReportActions.set_up(actions["report"])

        app.logger.info("Rule engine successfully initialized")
    except KeyError:
        raise AssertionError("Missing rules variables/actions in settings")


def verify_rule(rule):

    rtype = rule.get("rulesType")
    try:
        defined_actions = globals()["{}Actions".format(rtype)].methods
        defined_variables = globals()["{}Variables".format(rtype)].methods
    except KeyError:
        raise ValueError('Invalid rulesType "{}"'.format(rtype))

    conditions = rule["config"].get("conditions")
    if not conditions:
        raise ValueError("Missing conditions")

    _verify_conditions_recursively(conditions, defined_variables)

    try:
        actions = set([a["name"] for a in rule["config"]["actions"]])
        for action in actions:
            if action not in defined_actions:
                raise ValueError('Invalid action "{}"'.format(action))
    except KeyError:
        raise ValueError("Malformed actions")


def _verify_conditions_recursively(conditions, defined_variables):

    keys = list(conditions.keys())
    if keys == ["all"]:
        assert len(conditions["all"]) >= 1
        for condition in conditions["all"]:
            if not _verify_conditions_recursively(condition, defined_variables):
                return False
        return True

    elif keys == ["any"]:
        assert len(conditions["any"]) >= 1
        for condition in conditions["any"]:
            if _verify_conditions_recursively(condition, defined_variables):
                return True
        return False

    else:
        # help prevent errors - any and all can only be in the condition dict
        # if they're the only item
        assert not ("any" in keys or "all" in keys)
        if conditions["name"] not in defined_variables:
            raise ValueError('Invalid variable "{}"'.format(conditions["name"]))
        return True
