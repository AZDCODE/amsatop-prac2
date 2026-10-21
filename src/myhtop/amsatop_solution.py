import os
from typing import List

from amsatop import Htop, Process, TaskType
from amsatop.utils import get_stat_file_from_path


class Amsatop(Htop):
    def __init__(self):
        super().__init__()

    def get_processes(self) -> List[Process]:
        processes = []

        for entry in os.listdir(self.proc_folder):
            if not entry.isdigit():
                continue

            stat_path = os.path.join(self.proc_folder, entry, "stat")
            stat = get_stat_file_from_path(stat_path)

            if stat is None:
                continue

            if stat.flags & 0x00200000:
                task_type = TaskType.KTHREAD
            else:
                task_type = TaskType.PROCESS

            process = Process(
                pid=stat.pid,
                command=stat.command,
                type=task_type,
                priority=None
            )

            processes.append(process)

            # Els kthreads no els analitzem més
            if task_type == TaskType.KTHREAD:
                continue

            # Busquem els threads del procés
            task_path = os.path.join(self.proc_folder, entry, "task")

            try:
                threads = os.listdir(task_path)
            except OSError:
                continue

            for thread_id in threads:
                if not thread_id.isdigit():
                    continue

                # Evitem afegir el procés principal dues vegades
                if thread_id == entry:
                    continue

                thread_stat_path = os.path.join(
                    task_path, thread_id, "stat"
                )

                thread_stat = get_stat_file_from_path(thread_stat_path)

                # El thread pot haver desaparegut
                if thread_stat is None:
                    continue

                thread = Process(
                    pid=thread_stat.pid,
                    command=thread_stat.command,
                    type=TaskType.THREAD,
                    priority=None
                )

                processes.append(thread)

        return processes    
    
    def get_priorities(self) -> List[Process]:
        raise NotImplementedError("Prac-2.2 implementation needed")

    def get_hup(self) -> List[Process]:
        raise NotImplementedError("Prac-2.3 implementation needed")
