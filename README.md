# Alert Summarization for Online Service Systems by Validating Propagation Paths of Anomalies

![](https://github.com/cxl-for-anonymous/ProAlert/blob/main/figure/overview_6.pdf)

For an online service system, alerts are critical data for monitor-
ing the system as they record anomalies within the system. In a
real-world scenario, an anomaly can propagate through the topolog-
ical relationships between system components, triggering a large
number of alerts across various components. This makes tradi-
tional manual alert handling inadequate. Hence, there is an urgent
need for automatic alert summarization. In this paper, we propose
ProAlert, which summarizes alerts triggered by the same anomaly
into an incident by validating the propagation paths of anomalies.
ProAlert first unsupervisedly learns anomaly propagation patterns
from history alerts and system structure offline. Subsequently, it
employs the learned patterns to validate the propagation paths
of anomalies indicated by newly generated alerts online, thereby
accurately summarizing alerts. Additionally, the anomaly propa-
gation paths provided by ProAlert enhance the interpretability of
incidents, aiding maintenance engineers in understanding the un-
derlying anomalies. To demonstrate the effectiveness and efficiency
of ProAlert, we conduct extensive experiments on real-world data,
and find that ProAlert outperforms state-of-the-art approaches in
alert summarization.
