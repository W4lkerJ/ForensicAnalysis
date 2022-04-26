#!/usr/bin/env python
# coding: utf-8

# # Imports

# In[21]:


import json
import pandas as pd


# # Config

# ## Paths

# In[12]:


current_malware = "Cerber"


# In[13]:


config_path = "/home/jevenari/PycharmProjects/ForensicalAnalysis/config/config.json"
config = json.load(open(config_path, "r"))
config = config[current_malware]


# In[15]:


procmon_path = f"{config['Dynamic']}/{config['ProcessMonitor']}"


# ## Pandas

# In[39]:


pd.set_option('display.min_rows', 1000)
pd.set_option("display.max_rows", 10000)


# # Code

# In[ ]:





# # Analysis

# ## Load ProccessMonitor data

# In[43]:


df_procmon = pd.read_csv(procmon_path)


# In[60]:


df_procmon


# ## Get unique operations

# In[64]:


sorted(list(df_procmon["Operation"].unique()))


# ## Get Process Create/Process Exit/Process Start events)

# In[69]:


df_process_create = df_procmon.query("Operation == 'Process Create'")


# In[70]:


df_process_create


# In[73]:


df_process_start = df_procmon.query("Operation == 'Process Start'")


# In[74]:


df_process_start


# In[71]:


df_process_exit = df_procmon.query("Operation == 'Process Exit'")


# In[72]:


df_process_exit


# ## Get RegCreateKey/RegSetValue data

# In[67]:


df_reg_value_set = df_procmon.query("Operation == 'RegCreateKey'")


# In[68]:


df_reg_value_set


# In[65]:


df_reg_value_set = df_procmon.query("Operation == 'RegSetValue'")


# In[66]:


df_reg_value_set


# ## Get loaded DLLs

# In[42]:


df_loaded_dlls = df_procmon.query("Operation == 'Load Image'")


# In[50]:


unique_dlls = pd.unique(df_loaded_dlls["Path"])


# In[52]:


df_unique_dlls = pd.DataFrame(unique_dlls, columns=["Path"])


# In[57]:


df_unique_dlls["DLL"] = df_unique_dlls["Path"].apply(lambda path: path.split("\\")[-1])


# In[59]:


df_unique_dlls

