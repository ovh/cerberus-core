
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

    rule_elements = ["id", "config", "name", "rulesType", "orderId", "isActive"]
    for key in rule.keys():
        if key not in rule_elements:
            raise KeyError("Rule body is not correct")

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


def get_business_rules_variables():
    """ Get all the business rules variables. """
    config_groups = {
        "Report": _get_rules_type_config(ReportVariables),
        "CDNRequest": _get_rules_type_config(CDNRequestVariables),
        "EmailReply": _get_rules_type_config(EmailReplyVariables),
    }
    return _construct_config(config_groups)


def get_business_rules_actions():
    """ Get all the business rules actions. """
    config_groups = {
        "Report": _get_rules_type_config(ReportActions),
        "CDNRequest": _get_rules_type_config(CDNRequestActions),
        "EmailReply": _get_rules_type_config(EmailReplyActions),
    }
    return _construct_config(config_groups)


def _get_rules_type_config(config):
    """ Get Business Rules class variables. """
    rules_functions = []
    for class_elt in config.classes:
        if "get_all_variables" in dir(config):
            rules_functions += class_elt.get_all_variables()
        elif "get_all_actions" in dir(config):
            rules_functions += class_elt.get_all_actions()
    return rules_functions


def _construct_config(config_groups):
    """ Construct business rule variable response.
    It generates JSON array response from config elements.
    """
    config_response = []
    for (rules_type, config_list) in config_groups.items():
        for config in config_list:
            config["rulesType"] = rules_type
            config_response.append(config)
    return config_response


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
