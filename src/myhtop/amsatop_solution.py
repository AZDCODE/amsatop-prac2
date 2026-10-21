import os
from typing import List

from amsatop import Htop, Process, TaskType
from amsatop.utils import get_stat_file_from_path


class Amsatop(Htop):
    def __init__(self):
        super().__init__()

    def _thread_parents(self) -> dict[int, str]:
        parents = {}

        for pid in os.listdir(self.proc_folder):
            if not pid.isdigit():
                continue

            task_dir = os.path.join(self.proc_folder, pid, "task")

            try:
                threads = os.listdir(task_dir)
            except OSError:
                continue

            for tid in threads:
                if tid.isdigit() and tid != pid:
                    parents[int(tid)] = pid

        return parents

    def _task_file_path(
        self,
        process: Process,
        file_name: str,
        thread_parents: dict[int, str]
    ) -> str | None:

        if process.type == TaskType.THREAD:
            parent_pid = thread_parents.get(process.pid)

            if parent_pid is None:
                return None

            return os.path.join(
                self.proc_folder,
                parent_pid,
                "task",
                str(process.pid),
                file_name
            )

        return os.path.join(
            self.proc_folder,
            str(process.pid),
            file_name
        )
    
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
        processes = self.get_processes()
        result = []

        thread_parents = self._thread_parents()

        for process in processes:
            stat_path = self._task_file_path(
                process,
                "stat",
                thread_parents
            )

            if stat_path is None:
                continue

            stat = get_stat_file_from_path(stat_path)

            if stat is None:
                continue

            new_process = Process(
                pid=process.pid,
                command=process.command,
                type=process.type,
                priority=stat.priority
            )

            result.append(new_process)

        return result
    
    def get_hup(self) -> List[Process]:
        processes = self.get_priorities()
        result = []

        thread_parents = self._thread_parents()

        for process in processes:
            status_path = self._task_file_path(
                process,
                "status",
                thread_parents
            )

            if status_path is None:
                continue

            try:
                with open(status_path, encoding="utf-8") as file:
                    for line in file:
                        if line.startswith("SigIgn:"):
                            sig_ign = int(
                                line.partition(":")[2].strip(),
                                16
                            )

                            if sig_ign & 1:
                                result.append(process)

                            break

            except (OSError, ValueError):
                continue

        return result