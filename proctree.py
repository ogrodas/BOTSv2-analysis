from intake_splunk.core import SplunkConnect
from treelib import Tree,Node
import pandas as pd
import numpy as np

pd.set_option('display.max_rows', 1000)
pd.set_option('display.max_columns', 500)
pd.set_option('display.width', 1000)
pd.set_option('display.max_colwidth', 0)



class EventNode(Node):
    def __init__(self, tag=None, identifier=None, expanded=True, data=None):
        if not identifier:
            identifier=data["_cd"]
        super().__init__(tag, identifier, expanded, data)
        
class ProcessNode(EventNode):                
    @property
    def tag(self):
        return "{_time} Create Process {CommandLine} ({User})".format(**self.data)
    
class ComputerNode(Node):
    pass

class RemoteThreadNode(EventNode):                
    @property
    def tag(self):
        return "{_time}: Create Remote Thread {SourceImage} -> {TargetImage} {TargetProcessGuid}".format(**self.data)


class DriverLoadNode(EventNode):
    @property
    def tag(self):
        return "{_time} {EventDescription}: {ImageLoaded} {Hashes}".format(**self.data)

class FileCreateNode(EventNode):
    @property
    def tag(self):
        return "{_time} {EventDescription}: {TargetFilename}".format(**self.data)

class RegistryNode(EventNode):
    @property
    def tag(self):
        return "{_time} {EventDescription}: {object_path} -> {registry_value_name}".format(**self.data)

    
class NetworkNode(EventNode):
    @property
    def tag(self):
        return "{_time} {EventDescription}: {DestinationHostname} ({DestinationIp} {dest_port} Num:{num} Last:{last})".format(**self.data)
    
    
class ProcTree:
    """"
        s=SplunkConnect("https://localhost:8089")
        s.auth("admin","superadmin")
        SPL=s.read_pandas
    """
    def __init__(self,slunkconnect,prefix="index=botsv2 sourcetype=XmlWinEventLog:Microsoft-Windows-Sysmon/Operational",maxresult=5000):
        self.queries=[]
        self.tree=Tree()
        self.tree.create_node("query","query")
        self.df=pd.DataFrame()
        self.maxresult=maxresult
        self.s=slunkconnect
        self.prefix=prefix
        self.suffix="""| table _time, Computer, process_guid,parent_process_guid, process_image, 
   ParentCommandLine,CommandLine, EventDescription,User,DestinationHostname, 
   DestinationIp,dest_port, TargetFilename,ImageLoaded,Hashes,object_path,registry_value_name,
   SourceImage,TargetImage,SourceProcessGuid,TargetProcessGuid,_cd"""  
    
        
    def _run_query(self,query):
        self.queries.append(query)        
        q=self.prefix + " " + query + " " + self.suffix + f" | head {self.maxresult} "
        df=self.s.read_pandas(q)
        if len(df)== self.maxresult:
            print (f"WARNING: Results caped at {self.maxresult}")
        return df
        
    def query(self,query):        
        df=self._run_query(query)
        self.df=self.df.append(df).drop_duplicates()    
        self.build_tree(df)    
        return self
    
    def show(self): 
        self.tree.show()
        
    def _childprocsquery(self):
        return " OR ".join(f"parent_process_guid={p}" for p in self.df[self.df.process_guid.notnull()].process_guid)
        
    def addchildprocs(self,maxdepth=5):
        for i in range(maxdepth):
            q=self._childprocsquery()
            before=len(self.df)
            self.query(q)
            after=len(self.df)
            
            if after-before==0:
                print(f"Stopping after {i+1} iterations because no more data was found")
                return self
        print (f"WARNING: Stopping after {maxdepth} iterations without reaching all child procs")
        return self
    
    def _parentprocsquery(self):
        return " OR ".join(f"process_guid={p}" for p in self.df[self.df.parent_process_guid.notnull()].parent_process_guid)
    
    def addparentprocs(self,maxdepth=5):
        for i in range(maxdepth):
            q=self._parentprocsquery()
            before=len(self.df)
            self.query(q)
            after=len(self.df)
            
            if after-before==0:
                print(f"Stopping after {i+1} iterations")
                return self
        print (f"WARNING: Stopping after {maxdepth} iterations without reaching all parent procs")
        return self
    
    def _relatedprocssquery(self,filter):
        parentproc=self.df[self.df.parent_process_guid.notnull()].parent_process_guid
        proc=self.df[self.df.process_guid.notnull()].process_guid 
        allguids=proc.append(parentproc).drop_duplicates()
        procfilter=" OR ".join(f"{p}" for p in allguids) 
        if filter:
            return f"({procfilter}) AND ({filter})"
        else:
            return procfilter
        
    
    def addrelatedprocs(self,filter=None,maxdepth=5):
        for i in range(maxdepth):
            q=self._relatedprocssquery(filter)
            before=len(self.df)
            self.query(q)
            after=len(self.df)

            if after-before==0:
                print(f"Stopping after {i+1} iterations")
                return self
            
        print (f"WARNING: Stopping after {maxdepth} iterations without reaching all parent procs")
        return self
        
    def build_tree(self,df):
        #return
        t=self.tree
        if "Computer" not in df.columns:
            return

        for index,p in df.iterrows():
            computer=t.get_node(p.Computer)        
            if not computer:
                computer=ComputerNode(identifier=p.Computer)
                t.add_node(computer,"query")      

            if p.EventDescription=="Process Create":            
                #Here we have to deal with potentially missing parent processes. The query might not include the creation of the parent process
                parent=t.get_node(p.parent_process_guid)
                if not parent:                
                    parent=ProcessNode(identifier=p.parent_process_guid,data={"CommandLine":p.ParentCommandLine,"_time":p._time +"?","User":p.User,"_cd":p._cd})
                    t.add_node(parent,computer)


                #Here we have to deal with potentially already existing process. If a child process was process first for some reason that will add the parent as well. This can also happen with multple overlapping queries.
                process=t.get_node(p.process_guid)
                if process:
                    t.move_node(p.process_guid,p.parent_process_guid)
                    process.data=p.to_dict()
                #Normal case, Add process to tree
                else:
                    child=ProcessNode(identifier=p.process_guid,data=p.to_dict())
                    t.add_node(child,parent)

            elif p.EventDescription=="Process Terminate":
                process=t.get_node(p.process_guid)
                if process:
                    process.data["time_terminate"]=p._time
                else:
                    #Ignore terminating process that we have no other data on
                    pass
            else:

                #If node is not a process event but is already in tree continue. This can happen if there are multiple overlapping queries to build the tree
                if t.contains(p._cd):
                    continue

                if p.EventDescription=="Create Remote Thread":
                    #Here we have to deal with potentially missing source process
                    sourceProcess=t.get_node(p.SourceProcessGuid)
                    if not sourceProcess:
                        sourceProcess=ProcessNode(identifier=p.SourceProcessGuid,data={"CommandLine":"","_time":p._time,"User":p.User,"_cd":p._cd})
                        t.add_node(sourceProcess,computer)

                    #Add identifier
                    node=RemoteThreadNode(data=p.to_dict())
                    t.add_node(node,p.SourceProcessGuid)
 
                #Here we deal with the case if process is not existing for all the other events. For example a "Driver Load" event can referanse a process that is not part of the query. We then add the process to the tree witht the info we have
                proc=t.get_node(p.process_guid)
                if not proc:
                    proc=ProcessNode(identifier=p.process_guid,data={"CommandLine":p.ParentCommandLine,"_time":p._time + "???","User":p.User,"_cd":p._cd})
                    t.add_node(proc,computer)

                #Driver load
                if p.EventDescription=="Driver Load":
                    node=DriverLoadNode(data=p.to_dict())
                    t.add_node(node,p.process_guid)     

                #File Create Time and File Create
                if p.EventDescription.startswith("File Create"): 
                    node=FileCreateNode(data=p.to_dict())
                    t.add_node(node,p.process_guid)     

                #Registry value set and Registry object added or deleted
                if p.EventDescription.startswith("Registry"): 
                    node=RegistryNode(data=p.to_dict())
                    t.add_node(node,p.process_guid)  

                #Network
                if p.EventDescription.startswith("Network"):
                    identifier=f"{p.Computer} {p.DestinationHostname} {p.DestinationIp} {p.dest_port}"
                    node=t.get_node(identifier)
                    if node:
                        #TODO: Should compare before overwrite to make sure p._time is the largest
                        node.data["last"]=p._time
                        node.data["num"]+=1
                    else:
                        data=p.to_dict()
                        data["last"]=p._time
                        data["num"]=1
                        node=NetworkNode(identifier=identifier,data=data,expanded=False)
                        t.add_node(node,p.process_guid)
                    
                    subNode=Node(tag=f"{p._time}",identifier=p._cd)
                    t.add_node(subNode,node)
        return t