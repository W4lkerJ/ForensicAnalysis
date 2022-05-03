#!/usr/bin/env python
# coding: utf-8

# # Imports

# In[1]:


import json
import pandas as pd


# # Config

# ## Paths

# In[2]:


current_malware = "Cerber"


# In[3]:


project_root = "/home/jevenari/PycharmProjects/ForensicalAnalysis"


# In[4]:


config_path = "/home/jevenari/PycharmProjects/ForensicalAnalysis/config/config.json"
config = json.load(open(config_path, "r"))
config = config[current_malware]


# In[5]:


procmon_path = f"{config['Dynamic']}/{config['ProcessMonitor']}"


# In[6]:


regshot_path = f"{project_root}/data/{current_malware}/{config['Regshot']}"


# ## Pandas

# In[7]:


pd.set_option('display.min_rows', 1000)
pd.set_option("display.max_rows", 10000)


# # Process Monitor Analysis

# ## Load data

# In[8]:


df_procmon = pd.read_csv(procmon_path)


# In[9]:


df_procmon


# ## Get unique operations

# In[13]:


sorted(list(df_procmon["Operation"].unique()))


# ## Get Process Create/Process Exit/Process Start events)

# In[14]:


df_process_create = df_procmon.query("Operation == 'Process Create'")


# In[15]:


df_process_create


# In[16]:


df_process_start = df_procmon.query("Operation == 'Process Start'")


# In[17]:


df_process_start


# In[18]:


df_process_exit = df_procmon.query("Operation == 'Process Exit'")


# In[19]:


df_process_exit


# ## Get Thread Create/Thread Exit

# In[20]:


df_thread_create = df_procmon.query("Operation == 'Thread Create'")


# In[21]:


df_thread_create


# In[22]:


df_thread_exit = df_procmon.query("Operation == 'Thread Exit'")


# In[23]:


df_thread_exit


# ## Get RegCreateKey/RegSetValue data

# In[24]:


df_reg_value_set = df_procmon.query("Operation == 'RegCreateKey'")


# In[25]:


df_reg_value_set


# In[26]:


df_reg_value_set = df_procmon.query("Operation == 'RegSetValue'")


# In[27]:


df_reg_value_set.count()


# In[28]:


df_reg_value_set


# ## Get loaded DLLs

# In[29]:


df_loaded_dlls = df_procmon.query("Operation == 'Load Image'")


# In[30]:


unique_dlls = pd.unique(df_loaded_dlls["Path"])


# In[31]:


df_unique_dlls = pd.DataFrame(unique_dlls, columns=["Path"])


# In[32]:


df_unique_dlls["DLL"] = df_unique_dlls["Path"].apply(lambda path: path.split("\\")[-1])


# In[33]:


df_unique_dlls


# # Regshot Analysis

# ## Load data

# In[42]:


df_regshot_data = pd.read_csv(regshot_path, delimiter=";")


# ## Show unique types & operations

# In[50]:


sorted(df_regshot_data["Type"].unique())


# In[51]:


sorted(df_regshot_data["Operation"].unique())


# ## Files Created

# In[46]:


df_operation_query = df_regshot_data.query("Type == 'File' & Operation == 'Deleted'")


# In[47]:


df_operation_query


# In[49]:


df_operation_query.count()


# ## Files modified

# In[52]:


df_operation_query = df_regshot_data.query("Type == 'File' & Operation == 'Modified'")


# In[53]:


df_operation_query


# In[54]:


df_operation_query.count()


# ## Files Deleted

# In[79]:


df_operation_query = df_regshot_data.query("Type == 'File' & Operation == 'Deleted'")


# In[80]:


df_operation_query


# In[81]:


df_operation_query.count()


# ## Folders Created

# In[58]:


df_operation_query = df_regshot_data.query("Type == 'Folder' & Operation == 'Deleted'")


# In[59]:


df_operation_query


# In[60]:


df_operation_query.count()


# ## Folders modified

# In[61]:


df_operation_query = df_regshot_data.query("Type == 'Folder' & Operation == 'Modified'")


# In[62]:


df_operation_query


# In[64]:


df_operation_query.count()


# ## Folders Deleted

# In[76]:


df_operation_query = df_regshot_data.query("Type == 'Folder' & Operation == 'Deleted'")


# In[77]:


df_operation_query


# In[78]:


df_operation_query.count()


# ## Registry Keys Created

# In[67]:


df_operation_query = df_regshot_data.query("Type == 'Key' & Operation == 'Deleted'")


# In[68]:


df_operation_query


# In[69]:


df_operation_query.count()


# ## Registry Keys modified

# In[70]:


df_operation_query = df_regshot_data.query("Type == 'Key' & Operation == 'Modified'")


# In[71]:


df_operation_query


# In[72]:


df_operation_query.count()


# ## Registry Keys Deleted

# In[73]:


df_operation_query = df_regshot_data.query("Type == 'Value' & Operation == 'Deleted'")


# In[75]:


df_operation_query


# In[74]:


df_operation_query.count()


# ## Registry Values Created
# <h4 style="color: red">CAUTION: This part could not be parsed correctly, since the actual values were distributed over multiple lines resulting in a random pattern, that was impossible to parse.</h4>

# In[46]:


df_operation_query = df_regshot_data.query("Type == 'Value' & Operation == 'Deleted'")


# In[47]:


df_operation_query


# In[49]:


df_operation_query.count()


# ## Registry Values modified

# In[52]:


df_operation_query = df_regshot_data.query("Type == 'Value' & Operation == 'Modified'")


# In[53]:


df_operation_query


# In[54]:


df_operation_query.count()


# ## Registry Values Deleted

# In[55]:


df_operation_query = df_regshot_data.query("Type == 'Value' & Operation == 'Deleted'")


# In[56]:


df_operation_query.count()

