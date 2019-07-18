# BOTSv2 Analysis

Splunk has released a great dataset for testing log analysis and security monitoring use cases. The full name of the dataset is [Boss of the SOC (BOTS) Dataset Version 2](https://github.com/splunk/botsv2/). This repo contains my analysis. 

I learned a lot form working on this dataset and would recommend testing it!. I used most of the time on the analysis of the 24-26.aug attack on frothly.local. The other two need a bit more work. There might also be attacks that I have not discovered yet. 

Githubs nbviewer is sometimes failing. A good alternativ is [the official nbviewer](https://nbviewer.jupyter.org/github/ogrodas/BOTSv2-analysis/tree/master/)

**Basics**
* [Splunk setup](https://github.com/ogrodas/BOTSv2-analysis/blob/master/splunk.ipynb)
* [Sourcetypes](https://github.com/ogrodas/BOTSv2-analysis/blob/master/sourcetypes.ipynb)
* [Assets](https://github.com/ogrodas/BOTSv2-analysis/blob/master/assets.ipynb)

**Tools**

* [Sigma](https://github.com/ogrodas/BOTSv2-analysis/blob/master/sigma.ipynb)
* [ThreathuntingApp](https://github.com/ogrodas/BOTSv2-analysis/blob/master/threathuntingapp.ipynb)
* [Processtree](https://github.com/ogrodas/BOTSv2-analysis/blob/master/proctree.ipynb)

**Attack analysis**

* [11-15.aug www.brewertalk.com](https://github.com/ogrodas/BOTSv2-analysis/blob/master/11-15.aug%20attack%20on%20www.brewertalk.com.ipynb)
* [18-19.aug MACLORY-AIR13S](https://github.com/ogrodas/BOTSv2-analysis/blob/master/18-19.aug%20crypto%20virus%20on%20MACLORY-AIR13S.ipynb)
* [24-26.aug frothly.local](https://github.com/ogrodas/BOTSv2-analysis/blob/master/24-26.aug%20attack%20on%20frothly.ipynb)

## Some notes on definitions
In intrusion detection there is often talk about events, alarms, alerts, signatures, incidents and notifications and there does not seem to be a agreed upon definition. 

For the purpose of this analysis i'm going use the following definitions:

**Event:** A log of something that append. In the botsv2 dataset there are about 71 million events. There is no assumption that anyone are going to do anything about events. They are simply recored so that it is possible to discover what happed in the past.

**Alarm:** An alert is when a monitoring system detects something and raises this fact somewhere for further processing (and potentially triggers a notification as well). So an Alert is always in response to an event (in other words there is always an event with an alert) but there is not always an alert with an event. 

**Alert**
I'm going to consider an Alert an synonym for an Alarm

**Signature:** The pattern a monitoring system uses to detect alarms. All alarms are created from a signature. The signature "pattern" is meant to be interpreted broadly, it can be anything from a regexp to a machine learning model. Well known signature formats in intrusion detection is [Suricata rules](https://suricata.readthedocs.io/en/suricata-4.1.3/rules/intro.html), [Yara rules](https://github.com/Yara-Rules/rules), [Sigma rules](https://github.com/Neo23x0/sigma/tree/master/rules). 

**Incident:**
In ITIL v3 it is defined as “An unplanned interruption to an IT Service or a reduction in the Quality of an IT Service. Failure of a Configuration Item that has not yet impacted Service is also an Incident. For example, Failure of one disk from a mirror set.” Not all alerts are incidents, nor is there necessarily a 1:1 relation between alerts and incidents. Incidents can be linked to alerts, i.e. certain alerts indicate an incident. In many scenarios, alerts of certain severity are automatically transferred to an service management system and are the basis for the creation of an incident ticket.

**Notification:** Notifications are the very part that bring alerts and incidents to the attention of people that need to act and to respond.And here we are exactly arriving at the typical job our enterprise notification software does. Using multiple channels (voice, text, push, IM, etc), duty schedules, escalation plans, mobile apps and much more to automatically to notify operational staff upon alerts & incidents. I.e. deliver critical information to the right people at the right time and wherever they are.

**Recursion** is a source of confusion. An endpoint protection system might av a signature that triggers on some event and generates an alert. This alert is logged to a centralized log system(CLM) like Splunk.  In the CLM the alert can be considered both an event and an alert. There might be a problem that the endpoint protection platform generates to many alarms that have a high false positive rate(FPR) and it is not possible for an human to check every alarm. What might happen is that a new signature is made that generates an alarm if an endpoint has more that X number of endpoint protection alarms. In this scenario the endpoint detection alarms are events that are used for generating higher level alarms. In splunk this would normally be implemented as a saved search. The saved search in Splunk is what many call a correlation search and Splunk would be and example of what many call a Security Information and Event management system(SIEM)

Sources:
https://www.linkedin.com/pulse/definition-event-alert-incident-notification-matthes-derdack/

