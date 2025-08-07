rule test_rule : tag1 
{
    strings:
        $a = "Hello, world!"

    condition:
        any of them
}

rule no_alert_rule
{
    meta:
        modifiers = "no_alert"

    strings:
        $a = "This should not alert."

    condition:
        any of them
}

rule add_directive
{
    meta:
        modifiers = "directive=extract_urls"

    strings:
        $a = "This should have a directive to extract urls."

    condition:
        any of them
}

rule crits_rule
{
    strings:
        $5537d11dbcb87f5c8053ae55 = "CRITS id match"

    condition:
        any of them
}

rule test_whitelist : whitelisted
{
    strings:
        $a = "This should be whitelisted"

    condition:
        any of them
}

rule test_qa_modifier
{
    meta:
        modifiers = "qa"

    strings:
        $ = "Target with qa modifier."

    condition:
        any of them
}

rule detect_uri_path : detect_uri_path
{
    strings:
          $obs_1 = "test_uri_path" ascii wide nocase

    condition:
        any of them
}
